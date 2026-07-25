"""
sandboxed_worker.py

Runs INSIDE an already-namespace-isolated process (see sandbox_run.py,
which wraps this with `unshare --net --pid --mount-proc`). This script's
own job is the second layer of defense: drop root privileges to a real
unprivileged user and set hard resource limits BEFORE touching the user's
C code at all.

Critical lesson learned by testing this directly: RLIMIT_NPROC (and most
other rlimits) simply DO NOT APPLY to root. A fork bomb run as root, even
with RLIMIT_NPROC set, runs completely unrestricted. The same limit,
applied after dropping to an unprivileged uid, stopped a fork bomb after
19 forks. Setting rlimits while still root is close to security theater —
the privilege drop has to happen first, and it has to actually succeed.

Usage: python3 sandboxed_worker.py <path_to_c_source_file>
Writes a single JSON object to stdout: the same shape trace_extractor.py
produces, i.e. {"ok": bool, "steps": [...], "truncated": bool} or
{"ok": false, "error": "...", "detail": "..."}.
"""

import sys
import os
import pwd
import grp
import resource
import json
import traceback

SANDBOX_USER = "sandboxrunner"

# Resource ceilings. These are deliberately generous enough for small
# student programs but tight enough that abuse is bounded and cheap to
# recover from.
CPU_SECONDS = 10          # total CPU time for compiling + tracing
MAX_MEMORY_BYTES = 256 * 1024 * 1024   # 256 MB
MAX_PROCESSES = 25        # gcc + gdb + the traced inferior, with headroom
MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB — plenty for a compiled binary
MAX_OPEN_FILES = 64


def drop_privileges_and_limit_resources():
    """Must be called as root, exactly once, before anything untrusted runs."""
    if os.getuid() != 0:
        # Already unprivileged somehow (e.g. re-invoked) — nothing to drop.
        return

    user = pwd.getpwnam(SANDBOX_USER)
    group = grp.getgrgid(user.pw_gid)

    # Drop supplementary groups, then group, then user — order matters:
    # you must still be root to change your own group/supplementary groups,
    # so uid must be dropped LAST.
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)

    if os.getuid() == 0:
        # setuid silently no-op'd or something is very wrong — refuse to continue.
        print(json.dumps({"ok": False, "error": "sandbox_error",
                           "detail": "failed to drop root privileges"}))
        sys.exit(1)

    # Only now, as a real unprivileged user, do resource limits actually bind.
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN_FILES, MAX_OPEN_FILES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "sandbox_error", "detail": "usage: sandboxed_worker.py <source_file>"}))
        sys.exit(1)

    source_path = sys.argv[1]
    try:
        with open(source_path) as f:
            source_code = f.read()
    except Exception as e:
        print(json.dumps({"ok": False, "error": "sandbox_error", "detail": f"could not read source: {e}"}))
        sys.exit(1)

    drop_privileges_and_limit_resources()

    # Only import trace_extractor AFTER privileges are dropped and limits
    # are set — it's about to compile and execute the untrusted code.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import trace_extractor as te

    try:
        result = te.run_trace(source_code)
        print(json.dumps({
            "ok": True,
            "steps": result.steps,
            "truncated": result.truncated,
        }))
    except te.CompileError as e:
        print(json.dumps({"ok": False, "error": "compile_error", "detail": e.stderr}))
    except Exception as e:
        tb = traceback.format_exc()
        print(json.dumps({
            "ok": False,
            "error": "runtime_error",
            "detail": f"{type(e).__name__}: {e}",
            "traceback": tb,
        }))


if __name__ == "__main__":
    main()