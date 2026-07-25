"""
trace_extractor.py

Compiles a user's C source with debug symbols, then drives gdb via its
Machine Interface (MI) to single-step through the program and record a
JSON-serializable trace: source line, full call stack + locals at each
step, and a heap map built by breakpointing malloc/free.

Key lessons baked into this implementation:

  1. Use `-exec-step` (steps INTO calls), not `-exec-next` (steps OVER
     calls) — otherwise calls into the user's OWN functions (e.g. a
     recursive helper) are skipped as a single atomic step and you never
     see the recursion happen.

  2. Because `libc6-dbg` (or equivalent) is installed, glibc itself has
     debug info, so `-exec-step` will happily step INTO printf, malloc,
     free, etc. too. The fix is a general rule: any time we land in a
     frame that isn't the user's own source file, immediately
     `-exec-finish` back out of it and treat it as a single atomic step
     — UNLESS that frame is specifically malloc/free, which we want to
     intercept (see next point).

  3. Detect a malloc/free breakpoint hit by BREAKPOINT NUMBER, never by
     function name — glibc's actual symbol is something like
     `__GI___libc_malloc`, not literally "malloc". Breakpoints on
     malloc/free are only armed AFTER main() is reached, or you catch
     the dynamic linker's own internal allocator calls during startup.

  4. `-exec-finish` itself can be interrupted by hitting a breakpoint
     along the way (e.g. finishing out of `printf` can land you inside
     its internal `malloc` call for the stdio buffer) — every finish's
     result needs the same bkptno check as a step's result.

  5. Only track a malloc/free call in the heap map if its direct CALLER
     is the user's own source file — this filters out libc-internal
     allocations (like that same stdio buffer) that the user's code
     never actually gets a pointer to, which would otherwise show up as
     a confusing untracked heap block.

This module does NOT sandbox execution. It assumes it's being called
from a context that has already isolated the process (container/VM,
resource limits, no network). See README.md for the sandboxing story.
"""

import json
import os
import re
import signal
import subprocess
import tempfile
import shutil
import psutil
from pygdbmi.gdbcontroller import GdbController

MAX_STEPS = 500            # hard cap so an infinite loop can't run forever
GDB_TIMEOUT_SEC = 5         # per-command timeout for reading gdb responses
COMPILE_TIMEOUT_SEC = 10
MAX_FINISH_HOPS = 25        # safety bound when popping out of nested library frames
STEP_HARD_TIMEOUT_SEC = 6   # absolute wall-clock ceiling per step (see HardStepTimeout)


class HardStepTimeout(Exception):
    """Raised when a single step doesn't complete within STEP_HARD_TIMEOUT_SEC,
    no matter what gdb or the traced program are doing. This is the real
    safety net — some pathological programs (e.g. a trivial constant-condition
    infinite loop at -O0) can make gdb's own `step` implementation hang
    internally, which no amount of polling/interrupting from our side can
    reliably recover from. When this fires, we kill gdb's entire process
    tree (gdb + the traced inferior) and end the trace as truncated."""
    pass


def _kill_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except Exception:
                pass
        try:
            parent.kill()
        except Exception:
            pass
    except Exception:
        pass


class _StepAlarm:
    """Context manager: raises HardStepTimeout if the wrapped block doesn't
    finish within `seconds`. Linux-only (uses SIGALRM), which is fine since
    this is meant to run inside a Linux sandbox/container anyway."""
    def __init__(self, seconds):
        self.seconds = seconds

    def __enter__(self):
        self._old_handler = signal.signal(signal.SIGALRM, self._handler)
        signal.alarm(self.seconds)
        return self

    def _handler(self, signum, frame):
        raise HardStepTimeout()

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self._old_handler)
        return False


class CompileError(Exception):
    """Raised when the user's C code fails to compile."""
    def __init__(self, stderr):
        self.stderr = stderr
        super().__init__(stderr)


class TraceResult:
    def __init__(self):
        self.steps = []       # list of step dicts
        self.truncated = False


def compile_c(source_code, workdir):
    """Write source to disk and compile with -g -O0. Raises CompileError on failure."""
    src_path = os.path.join(workdir, "prog.c")
    bin_path = os.path.join(workdir, "prog")

    with open(src_path, "w") as f:
        f.write(source_code)

    proc = subprocess.run(
        ["gcc", "-g", "-O0", "-fno-omit-frame-pointer", "-o", bin_path, src_path],
        capture_output=True, text=True, timeout=COMPILE_TIMEOUT_SEC
    )
    if proc.returncode != 0:
        raise CompileError(proc.stderr)
    return bin_path, src_path


def _extract_hex_addr(value_str):
    if not value_str:
        return None
    m = re.search(r"0x[0-9a-fA-F]+", value_str)
    return m.group(0) if m else None


def _send_and_wait_for_stop(gdbmi, command, overall_budget_sec=4):
    """Send an async command (-exec-step, -exec-finish, -exec-run) and keep
    reading gdb's output — without sending anything else — until we see a
    real 'stopped' notification or a program-exit indication.

    This works around a real flakiness: on very fast/tight loops, pygdbmi's
    first read can return with only 'running' notifications, before the
    eventual 'stopped' notification has actually arrived. Blindly issuing
    another command at that point desyncs the conversation. Instead we keep
    polling for pending output on the SAME in-flight command.

    If nothing arrives within `overall_budget_sec` (this does happen on
    certain pathological tight loops with no clean line-boundary signal),
    we forcibly interrupt execution (like Ctrl-C) rather than hang —
    guaranteeing this function always returns in bounded time.
    """
    all_msgs = list(gdbmi.write(command, timeout_sec=2, raise_error_on_timeout=False))
    elapsed = 0.0
    poll = 0.5
    while elapsed < overall_budget_sec:
        if _first_stopped_payload(all_msgs) is not None or _program_exited(all_msgs):
            return all_msgs
        more = gdbmi.get_gdb_response(timeout_sec=poll, raise_error_on_timeout=False)
        if more:
            all_msgs.extend(more)
        else:
            elapsed += poll

    # Budget exhausted — force a stop so we never hang indefinitely.
    try:
        interrupt_resp = gdbmi.write("-exec-interrupt", timeout_sec=2, raise_error_on_timeout=False)
        all_msgs.extend(interrupt_resp)
        more = gdbmi.get_gdb_response(timeout_sec=2, raise_error_on_timeout=False)
        if more:
            all_msgs.extend(more)
    except Exception:
        pass
    return all_msgs


def _bkpt_number(gdb_responses):
    for msg in gdb_responses:
        if msg.get("message") == "done":
            payload = msg.get("payload") or {}
            bkpt = payload.get("bkpt")
            if bkpt:
                return bkpt.get("number")
    return None


def _first_stopped_payload(gdb_responses):
    for msg in gdb_responses:
        if msg.get("type") == "notify" and msg.get("message") == "stopped":
            return msg.get("payload") or {}
    return None


def _program_exited(gdb_responses):
    payload = _first_stopped_payload(gdb_responses)
    if payload and payload.get("reason") in ("exited-normally", "exited"):
        return True
    # Some gdb versions report thread-group-exited instead
    for msg in gdb_responses:
        if msg.get("message") in ("thread-group-exited", "thread-exited"):
            return True
    return False


def _locals_at_frame(gdbmi, thread_id, level):
    out = {}
    try:
        resp = gdbmi.write(
            f"-stack-list-variables --thread {thread_id} --frame {level} --simple-values",
            timeout_sec=GDB_TIMEOUT_SEC
        )
        for msg in resp:
            if msg.get("message") == "done":
                for v in (msg["payload"].get("variables") or []):
                    val = v.get("value")
                    out[v.get("name")] = val.strip() if val else val
    except Exception:
        pass
    return out


def _args_at_frame0(gdbmi, thread_id):
    """Return the list of argument values (in order) for the innermost frame."""
    values = []
    try:
        resp = gdbmi.write(f"-stack-list-arguments --thread {thread_id} --frame 0 1", timeout_sec=GDB_TIMEOUT_SEC)
        for msg in resp:
            if msg.get("message") == "done":
                stack_args = msg["payload"].get("stack-args", [])
                if stack_args:
                    for a in stack_args[0].get("args", []):
                        values.append(a.get("value"))
    except Exception:
        pass
    return values


def _raw_stack(gdbmi, thread_id):
    try:
        resp = gdbmi.write(f"-stack-list-frames --thread {thread_id}", timeout_sec=GDB_TIMEOUT_SEC)
        for msg in resp:
            if msg.get("message") == "done":
                return [e.get("frame", e) for e in msg["payload"].get("stack", [])]
    except Exception:
        pass
    return []


def _full_stack_with_locals(gdbmi, thread_id, src_path):
    """Full call stack (innermost first). Frames belonging to the user's own
    source file get their locals resolved; library frames are tagged but
    left empty (cheaper, and irrelevant to the visualization)."""
    frames = []
    for frame in _raw_stack(gdbmi, thread_id):
        level = int(frame.get("level", 0))
        is_user = frame.get("fullname") == src_path
        frames.append({
            "func": frame.get("func", "??"),
            "line": int(frame["line"]) if frame.get("line") else None,
            "is_user_code": is_user,
            "locals": _locals_at_frame(gdbmi, thread_id, level) if is_user else {},
        })
    return frames


def _caller_is_user_code(gdbmi, thread_id, src_path):
    """Is the frame that called the CURRENT (innermost) function the user's
    own source file? Used to filter out libc-internal allocations (e.g.
    stdio's first-write buffer malloc) that the user's code never sees a
    pointer to."""
    stack = _raw_stack(gdbmi, thread_id)
    if len(stack) > 1:
        return stack[1].get("fullname") == src_path
    return False


def run_trace(source_code):
    """
    Compile + trace `source_code`. Returns a TraceResult.
    Raises CompileError if the code doesn't compile.
    """
    result = TraceResult()
    workdir = tempfile.mkdtemp(prefix="tracebackend_")
    heap = {}  # addr -> {"size": int}

    try:
        bin_path, src_path = compile_c(source_code, workdir)

        # pygdbmi defaults to waiting 0.2s after each read to check for
        # more output. That's a fixed floor on EVERY MI round-trip — with a
        # deep call stack (recursion) we make many small queries per step
        # (one -stack-list-variables per frame), and 0.2s each compounds
        # fast: a 26-step recursive+heap trace took 25s total, ~16s of
        # which was pure per-call overhead, not gdb actually doing work.
        # Lowering this to 0.02s cut that overhead by roughly 10x with no
        # correctness change (still confirmed via _send_and_wait_for_stop's
        # own polling loop for the async step/finish commands).
        #
        # The initial setup sequence below (load binary, arm breakpoints,
        # run to main) is wrapped in a retry loop: on one WSL2 test run,
        # gdb died silently (BrokenPipeError on the very next MI command)
        # in the split second between two back-to-back setup commands, for
        # reasons outside our control (almost certainly WSL2's virtualized
        # ptrace layer hiccupping, not a logic bug — the exact same
        # sequence succeeded moments earlier and later on the same
        # machine). Rather than fail the whole trace on a transient hiccup
        # during this narrow setup window, we retry with a completely
        # fresh gdb session a few times before giving up.
        gdbmi = None
        malloc_num = None
        free_num = None
        MAX_SETUP_ATTEMPTS = 3

        for attempt in range(1, MAX_SETUP_ATTEMPTS + 1):
            if gdbmi is not None:
                try:
                    if gdbmi.gdb_process:
                        _kill_process_tree(gdbmi.gdb_process.pid)
                except Exception:
                    pass

            gdbmi = GdbController(
                command=["gdb", "--nx", "--quiet", "--interpreter=mi3"],
                time_to_check_for_additional_output_sec=0.02,
            )

            try:
                gdbmi.write(f"-file-exec-and-symbols {bin_path}", timeout_sec=GDB_TIMEOUT_SEC)
                gdbmi.write("-break-insert main", timeout_sec=GDB_TIMEOUT_SEC)
                _send_and_wait_for_stop(gdbmi, "-exec-run")

                # Only NOW arm malloc/free — after the dynamic linker's own
                # startup allocations are already done.
                malloc_resp = gdbmi.write("-break-insert malloc", timeout_sec=GDB_TIMEOUT_SEC)
                free_resp = gdbmi.write("-break-insert free", timeout_sec=GDB_TIMEOUT_SEC)
                malloc_num = _bkpt_number(malloc_resp)
                free_num = _bkpt_number(free_resp)
                break  # setup succeeded — proceed with this gdb session
            except (BrokenPipeError, OSError) as e:
                if attempt >= MAX_SETUP_ATTEMPTS:
                    raise
                print(f"[trace_extractor] gdb setup attempt {attempt} failed "
                      f"({type(e).__name__}: {e}) — retrying with a fresh session.")
                continue

        def snapshot(message=""):
            if len(result.steps) >= MAX_STEPS:
                raise RuntimeError("__TRACE_TRUNCATED__")
            stack = _full_stack_with_locals(gdbmi, "1", src_path)
            top_line = next((f["line"] for f in stack if f["is_user_code"]), None)
            result.steps.append({
                "line": top_line,
                "stack": stack,
                "heap": [{"addr": a, **info} for a, info in heap.items()],
                "message": message,
            })

        try:
            snapshot("Program started.")
            finished = False

            def handle_malloc():
                """We're stopped at the malloc breakpoint. Capture size + return
                value, decide whether to track it, and return once we're back
                in *some* caller frame."""
                is_user_call = _caller_is_user_code(gdbmi, "1", src_path)
                size_val = 0
                if is_user_call:
                    args = _args_at_frame0(gdbmi, "1")
                    if args:
                        digits = re.sub(r"[^0-9]", "", args[0] or "")
                        size_val = int(digits) if digits else 0

                finish_resp = _send_and_wait_for_stop(gdbmi, "-exec-finish")
                returned_addr = None
                for msg in finish_resp:
                    p = msg.get("payload") or {}
                    if isinstance(p, dict) and "return-value" in p:
                        returned_addr = _extract_hex_addr(p["return-value"])

                if is_user_call and returned_addr:
                    heap[returned_addr] = {"size": size_val}
                    snapshot(f"malloc({size_val}) -> {returned_addr}")
                return finish_resp

            def handle_free():
                is_user_call = _caller_is_user_code(gdbmi, "1", src_path)
                addr = None
                if is_user_call:
                    args = _args_at_frame0(gdbmi, "1")
                    addr = _extract_hex_addr(args[0]) if args else None

                finish_resp = _send_and_wait_for_stop(gdbmi, "-exec-finish")

                if is_user_call:
                    if addr and addr in heap:
                        del heap[addr]
                    snapshot(f"free({addr})")
                return finish_resp

            while not finished:
                try:
                    with _StepAlarm(STEP_HARD_TIMEOUT_SEC):
                        resp = _send_and_wait_for_stop(gdbmi, "-exec-step")

                        hops = 0
                        while True:
                            if _program_exited(resp):
                                finished = True
                                break

                            payload = _first_stopped_payload(resp)
                            if payload is None:
                                # No usable stop info — bail out of this inner
                                # loop and let the outer loop try another step.
                                break

                            bkptno = payload.get("bkptno")

                            if bkptno == malloc_num:
                                resp = handle_malloc()
                                hops += 1
                                if hops > MAX_FINISH_HOPS:
                                    break
                                continue

                            if bkptno == free_num:
                                resp = handle_free()
                                hops += 1
                                if hops > MAX_FINISH_HOPS:
                                    break
                                continue

                            frame = payload.get("frame", {})
                            if frame.get("fullname") == src_path:
                                snapshot()
                                break  # back to outer loop for the next step

                            # Stepped into some non-user, non-malloc/free frame
                            # (e.g. printf's internals) — treat as atomic, pop out.
                            resp = _send_and_wait_for_stop(gdbmi, "-exec-finish")
                            hops += 1
                            if hops > MAX_FINISH_HOPS:
                                break

                except HardStepTimeout:
                    # gdb itself got stuck stepping through this particular
                    # program (rare, but real — e.g. certain trivial constant-
                    # condition infinite loops at -O0). No amount of polling
                    # can recover this gracefully, so we kill the whole
                    # gdb + inferior process tree and end the trace here.
                    result.truncated = True
                    if gdbmi.gdb_process:
                        _kill_process_tree(gdbmi.gdb_process.pid)
                    finished = True
                except RuntimeError as e:
                    if str(e) == "__TRACE_TRUNCATED__":
                        result.truncated = True
                    finished = True
                except Exception:
                    finished = True

        except RuntimeError as e:
            if str(e) == "__TRACE_TRUNCATED__":
                result.truncated = True
            else:
                raise

        try:
            gdbmi.exit()
        except Exception:
            pass

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return result


if __name__ == "__main__":
    import sys
    code = sys.stdin.read()
    try:
        trace = run_trace(code)
        print(json.dumps({
            "ok": True,
            "steps": trace.steps,
            "truncated": trace.truncated,
        }, indent=2))
    except CompileError as e:
        print(json.dumps({"ok": False, "error": "compile_error", "detail": e.stderr}))