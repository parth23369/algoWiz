# trace_extractor.py — C execution trace backend

Compiles user-submitted C, drives real `gdb` via its Machine Interface (MI),
and produces a step-by-step JSON trace: source line, full call stack with
locals at each frame, and a heap map built by intercepting `malloc`/`free`.

This now includes a working sandbox layer (`sandboxed_worker.py` +
`sandbox_run.py`), a minimal API (`app.py`), and a frontend integration
(a fifth "C / Memory" type in `code-visualizer.html`) — all tested end to
end against a real running backend, not just described.

## Architecture

```
code-visualizer.html (frontend)
        │  fetch POST /run  {code: "..."}
        ▼
     app.py (Flask)
        │
        ▼
  sandbox_run.py  ── unshare --net --pid --mount-proc --fork ──▶  isolated namespace
        │                                                              │
        │                                                              ▼
        │                                                    sandboxed_worker.py
        │                                                    (drops root → sandboxrunner,
        │                                                     sets rlimits, THEN imports
        │                                                     and runs trace_extractor)
        ▼
   JSON trace  ◀── stdout ──────────────────────────────────────────────┘
```

## Usage

Standalone (no sandbox, for local testing against your own files):
```bash
python3 trace_extractor.py < your_program.c > trace.json
```

Through the sandbox (what the API actually uses):
```bash
python3 sandbox_run.py < your_program.c
```

As a live API:
```bash
python3 app.py   # http://0.0.0.0:5001
curl -X POST http://localhost:5001/run -H "Content-Type: application/json" \
     -d '{"code": "int main() { return 0; }"}'
```

Output shape:

```json
{
  "ok": true,
  "truncated": false,
  "steps": [
    {
      "line": 9,
      "message": "malloc(12) -> 0x5555555592a0",
      "heap": [{"addr": "0x5555555592a0", "size": 12}],
      "stack": [
        {
          "func": "main",
          "line": 9,
          "is_user_code": true,
          "locals": {"a": "5", "b": "10", "sum": "15", "arr": "0x5555555592a0"}
        }
      ]
    }
  ]
}
```

On a compile error: `{"ok": false, "error": "compile_error", "detail": "<gcc stderr>"}`.
On a timeout: `{"ok": false, "error": "timeout", "detail": "..."}`.

## Real bugs hit while building this (worth knowing if you extend it)

### In the tracer itself

1. **Arming `malloc`/`free` breakpoints before `main()` runs catches the
   dynamic linker's own startup allocations**, not the user's code. Fix:
   only insert those breakpoints *after* the initial breakpoint at `main`
   has already been hit.

2. **glibc's actual malloc symbol isn't `"malloc"`** — it's something like
   `__GI___libc_malloc`. Never match on function name; match on the
   breakpoint *number* gdb assigns when you insert the breakpoint.

3. **`-exec-next` steps OVER function calls** — including calls into the
   user's *own* functions. A recursive function would show as a single
   atomic step with no visible recursion. Fix: use `-exec-step` instead,
   which steps *into* calls — but only calls with debug info.

4. **Because `libc6-dbg` is installed, glibc has debug info too**, so
   `-exec-step` will happily dive into `printf`'s internals, not just the
   user's code. Fix: after every step, check whether the stopped frame's
   `fullname` matches the user's own source file. If it doesn't (and it's
   not a `malloc`/`free` breakpoint hit), immediately `-exec-finish` back
   out and treat the whole call as one atomic step.

5. **`-exec-finish` can itself be interrupted by a breakpoint** along the
   way — e.g. finishing out of `printf` can land you inside its internal
   `malloc` call for the stdio output buffer. Every `finish` response needs
   the same breakpoint-number check as a step's response.

6. **Filter heap tracking to allocations directly called from user code.**
   Without this, that same stdio buffer allocation shows up as an
   untracked, confusing heap block the user's code never has a pointer to.
   Check whether the *caller* of the current malloc/free is the user's
   source file before tracking it.

7. **pygdbmi can return before the real `'stopped'` notification arrives**,
   especially on fast/tight loops — you get `['running', 'running']` with
   no stop, and the *next* command's read ends up desynced. Fix: after
   issuing a step/finish/run, keep polling `get_gdb_response()` (which reads
   pending output *without* sending a new command) until a real `stopped`
   or exit notification shows up, rather than assuming one `write()` call
   always captures the full response.

8. **Some trivial programs can make gdb's own `step` hang internally** —
   e.g. `while (1) { i++; }` at `-O0`, where the compiler may elide the
   constant-`1` condition check entirely, leaving no clean line-boundary
   for gdb's line-stepping logic to key off of. Polling and even
   `-exec-interrupt` weren't reliable recovery mechanisms for this specific
   case. The real fix: a hard wall-clock ceiling (`SIGALRM`) around every
   step that, on firing, force-kills gdb's entire process tree (gdb + the
   traced inferior) via `psutil` and ends the trace as truncated.

9. **pygdbmi's default 0.2s post-read polling delay is a fixed floor on
   every single MI round-trip.** With a deep call stack (recursion), each
   snapshot queries locals once per frame — a 26-step trace with recursion
   depth 5 took 25s, ~16s of which was pure per-call overhead, not gdb
   doing actual work. Fix: `GdbController(..., time_to_check_for_additional_output_sec=0.02)`
   cut that overhead roughly 10x with no correctness change. This mattered
   in practice — at the original speed, this exact trace blew past the
   sandbox's 25s overall timeout and got reported as a false "infinite
   loop," when the code was completely correct and just running through a
   slow tracer.

### In the sandbox layer

10. **`RLIMIT_NPROC` (and most rlimits) simply do not apply to root.**
    Tested directly: a fork bomb run as root with `RLIMIT_NPROC` set ran
    completely unrestricted. The identical limit, applied *after* dropping
    to a real unprivileged user, stopped the same fork bomb after 19 forks.
    Setting resource limits while still root is close to security theater
    — the privilege drop has to happen first, and has to actually succeed
    (verified by checking `os.getuid() != 0` after the drop, not assumed).

11. **`subprocess.run(..., timeout=N)` only kills the direct child
    process on timeout — not the process tree it spawned.** Since
    `unshare --fork` immediately forks into the new PID namespace, the
    original `unshare` process can exit right away, detaching the actual
    worker (and anything it forks, like a fork bomb's descendants) from
    the one PID the caller has a handle to. Verified the hard way: a
    fork-bomb test left ~20 processes pegged at full CPU indefinitely even
    after `subprocess.run` reported a clean timeout. Fix: launch with
    `start_new_session=True` (own process group) and, on timeout or even
    on the normal completion path, `os.killpg(os.getpgid(pid), SIGKILL)` —
    reaches every descendant, not just the one PID originally spawned.

## What's actually verified (not just claimed)

- Network isolation: a real `connect()` call in submitted C returns `-1`
  (fails) when run inside the `unshare --net` namespace — confirmed with
  actual malicious C, not a mock.
- Fork bomb: stopped by `RLIMIT_NPROC` (after privilege drop), and its
  process-group kill leaves **zero** leftover processes (checked via `ps
  aux` immediately after and 2s later).
- Full pipeline tested with real HTTP requests (curl and a jsdom-simulated
  browser actually clicking through the frontend's `Compile & Trace`
  button) against a live `app.py` instance — not just unit-level calls to
  `run_trace()`.
- Frontend correctly renders recursion depth (multiple stack frames
  simultaneously visible), a growing/shrinking heap map, and a compile
  error / unreachable-backend error path.

## Remaining gap: this is namespace isolation, not container isolation

`unshare --net --pid` + privilege drop + rlimits meaningfully raises the
bar over "just run gcc and gdb directly," and every claim above is tested,
not assumed. It is **still not full container/microVM isolation**
(gVisor/Firecracker) — Docker wasn't available in this environment to
build/test that layer, so it remains a documented gap rather than a
verified one:

- No seccomp syscall filtering — a kernel exploit reachable via `ptrace`
  or any other syscall this environment allows is still a real risk this
  setup does not close.
- No filesystem isolation beyond what the unprivileged user can already
  read — `chroot`/read-only bind mounts are not yet in place.
- Single-host, no rate limiting or request queue — many concurrent
  requests would compete for the same CPU/memory with no fairness
  guarantee.

Before exposing this to actual strangers, add gVisor or Firecracker-level
isolation on top of what's here, plus rate limiting and a request queue.

## Frontend integration

`code-visualizer.html` now has a fifth type, **"C / Memory (real gdb
backend)"**. Unlike the other four, it needs no `viz.*` API calls — you
paste real, unmodified C, point the "Backend URL" field at a running
`app.py`, and press "Compile & Trace." The response is rendered as two
columns: a call stack (each frame showing its own locals, so recursion
depth is genuinely visible — not simulated) and a heap region, with
pointer variables color-matched to the heap block they point to. It plugs
into the exact same Step/Play/Reset/speed-slider engine as the other four
types.

## Running it yourself

```bash
pip install -r requirements.txt
useradd -M -s /usr/sbin/nologin sandboxrunner   # one-time setup
python3 app.py                                   # starts on :5001
# then open code-visualizer.html, select "C / Memory", point Backend URL
# at http://localhost:5001, and press Compile & Trace.
```