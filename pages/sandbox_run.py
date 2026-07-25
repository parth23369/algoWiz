"""
sandbox_run.py

The outer layer. Responsibilities:
  1. Write the user's C source to a private, restricted-permission temp file.
  2. Launch sandboxed_worker.py inside a fresh network + PID namespace via
     `unshare --net --pid --mount-proc --fork`, so the traced program has
     no network interfaces at all (verified: connect() fails immediately
     with ENETUNREACH inside the namespace, vs. the host's own network
     behavior outside it) and can't see or signal other processes on the
     host.
  3. Enforce a hard overall wall-clock ceiling independent of anything
     happening inside — if the whole pipeline (compile + trace) doesn't
     finish in time, kill it and report a timeout rather than hang the
     API server.
  4. Always clean up the temp file/dir, even on failure.

This is layered on top of (not a replacement for) sandboxed_worker.py's
own privilege drop + resource limits — defense in depth: namespace
isolation stops network/process-visibility abuse, rlimits stop resource
exhaustion, and this wall-clock ceiling stops anything that slips past
both.

Known gap (see README.md): this is namespace + rlimit isolation, not full
container/microVM isolation (gVisor/Firecracker). It meaningfully raises
the bar over "just run gcc and gdb directly" but is not a substitute for
running each request in its own throwaway container in a real deployment.
"""

import subprocess
import tempfile
import os
import signal
import shutil
import json
import time

OVERALL_TIMEOUT_SEC = 25   # compile + full trace, hard ceiling
WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandboxed_worker.py")


def _try_unshare_available():
    """Quick probe: can we actually run the EXACT unshare invocation the
    real code uses — same flags AND same subprocess launch conditions?
    This must match precisely. Confirmed the hard way: on one WSL2 build,
    testing with plain subprocess.run() succeeded, while the real call
    (which uses start_new_session=True, needed so we can killpg the whole
    process group later) still failed — the new-session context itself
    seems to affect whether unshare is permitted. So the probe now
    replicates start_new_session=True too, not just the flag list."""
    try:
        probe = subprocess.Popen(
            ["unshare", "--net", "--pid", "--mount-proc", "--fork", "--", "true"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        _, stderr = probe.communicate(timeout=5)
        if probe.returncode != 0:
            print(f"[sandbox_run.py] unshare probe failed (rc={probe.returncode}): {stderr.strip()}")
        return probe.returncode == 0
    except Exception as e:
        print(f"[sandbox_run.py] unshare probe raised an exception: {e}")
        return False


_UNSHARE_AVAILABLE = _try_unshare_available()

if not _UNSHARE_AVAILABLE:
    print(
        "\n[sandbox_run.py] WARNING: 'unshare --net' is not permitted on this "
        "system (common on WSL2) — network/PID namespace isolation is "
        "DISABLED. Privilege drop, resource limits, and the wall-clock "
        "timeout still apply. This is fine for running your own trusted "
        "code locally, but do not expose this backend to untrusted "
        "submissions in this configuration.\n"
    )


def run_sandboxed(source_code: str) -> dict:
    """Compile + trace `source_code` inside the sandbox. Always returns a
    dict with at least an "ok" key — never raises for well-formed input."""
    workdir = tempfile.mkdtemp(prefix="sandboxreq_")
    source_path = os.path.join(workdir, "submission.c")

    try:
        with open(source_path, "w") as f:
            f.write(source_code)
        os.chmod(source_path, 0o644)
        # Sandbox user needs to be able to traverse into this directory.
        os.chmod(workdir, 0o755)

        if _UNSHARE_AVAILABLE:
            cmd = [
                "unshare",
                "--net",            # no network interfaces at all inside
                "--pid",             # can't see/signal host processes
                "--mount-proc",      # needed for a sane /proc inside the new PID ns
                "--fork",             # required when combined with --pid
                "--",
                "python3", WORKER_SCRIPT, source_path,
            ]
        else:
            # Fall back to running the worker directly — no network/PID
            # namespace isolation (known gap on platforms like WSL2, where
            # `unshare --net` is blocked even as root), but privilege drop,
            # resource limits, and the wall-clock timeout below still apply.
            cmd = ["python3", WORKER_SCRIPT, source_path]

        # IMPORTANT: subprocess.run(..., timeout=N) only kills the DIRECT
        # child on timeout. But `unshare --fork` immediately forks into the
        # new PID namespace and the outer `unshare` process can exit right
        # away, detaching the real worker (and anything IT forks, like a
        # fork bomb's descendants) from the handle we hold. Verified this
        # the hard way: a fork-bomb test kept ~20 processes pegged at full
        # CPU indefinitely even after subprocess.run reported a clean
        # timeout. Fix: launch with start_new_session=True so the whole
        # invocation gets its own process GROUP, and on timeout kill the
        # entire group with os.killpg — that reaches every descendant,
        # not just the one PID we happen to have a handle to.
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

        try:
            stdout, stderr = proc.communicate(timeout=OVERALL_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc.pid)
            try:
                proc.communicate(timeout=3)
            except Exception:
                pass
            return {
                "ok": False,
                "error": "timeout",
                "detail": f"Execution exceeded the {OVERALL_TIMEOUT_SEC}s overall time limit.",
            }
        finally:
            # Belt and suspenders: even on the success path, make sure
            # nothing from this process group survives the request.
            _kill_process_group(proc.pid, quiet=True)

        if not stdout.strip():
            return {
                "ok": False,
                "error": "sandbox_error",
                "detail": f"No output from sandboxed worker. stderr: {stderr[:500]}",
            }

        try:
            return json.loads(stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return {
                "ok": False,
                "error": "sandbox_error",
                "detail": f"Worker produced non-JSON output: {stdout[:500]}",
            }

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _kill_process_group(pid, quiet=False):
    """Kill the entire process group rooted at pid. Used both on timeout
    and defensively on the normal-completion path."""
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # already gone — fine
    except Exception as e:
        if not quiet:
            print(f"warning: failed to kill process group for pid {pid}: {e}")


if __name__ == "__main__":
    # Quick manual smoke test: python3 sandbox_run.py < some_file.c
    import sys
    code = sys.stdin.read()
    print(json.dumps(run_sandboxed(code), indent=2))