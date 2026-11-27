# algoWiz

Browser-based algorithm visualizations (sorting, graphs, dynamic programming,
greedy, backtracking, divide and conquer), plus a code visualizer. The
visualizer's **C / Memory** type compiles your C with `gcc`, steps through it
with `gdb` on a small Flask backend, and shows the call stack and heap at each
step.

> **Do not expose the backend to people you do not trust.** The containers limit
> what submitted code can do, but submitted code can still kill or freeze the
> server. See [what is not limited](#what-the-containers-do-not-limit).

## Layout

```
index.html                  home page
pages/                      topic pages, code-visualizer.html, visualizations/
pages/app.py                Flask API: POST /run, GET /health
pages/sandbox_run.py        starts each request, enforces the 25 s limit, cleans up
pages/sandboxed_worker.py   applies per-process resource limits
pages/trace_extractor.py    compiles and traces with gdb
pages/README.md             backend design notes
Dockerfile, docker-compose.yml, docker/nginx.conf
tests/                      pytest suite, security checks, behaviour check
```

## Run it

**Pages** (no Docker needed). Links are absolute (`/pages/...`), so serve from
the repository root:

```bash
python3 -m http.server 8000        # then open http://localhost:8000
```

**C / Memory backend** (needs Docker Engine 28.0 or newer and Compose v2):

```bash
docker compose up -d --build --wait     # backend on http://localhost:5001
docker compose down                     # stop
```

Open the code visualizer, choose **C / Memory**, keep the backend URL
`http://localhost:5001`, and press **Compile & Trace**.

```
browser ──> localhost:5001 ──> proxy (nginx) ──> backend (Flask, gcc, gdb)
                               edge + sandbox     sandbox network only
```

The proxy exists because a port cannot be published from an internal network.

## Docker version

**Minimum: Docker Engine 28.0**, the release that added the
[isolated gateway mode](https://github.com/moby/moby/releases/tag/v28.0.0).
Check with `docker version` (the **Server** version).

| Engine | What `docker compose up` does |
|---|---|
| 29.9.3 | Works. All results below come from this version. |
| 28.0.x | Expected to work, from the release notes. **Not tested.** |
| 27.5.1 | Fails with the error below. |
| 24.0.7 | **Starts with no error, and submitted code can reach services on the Docker host.** |

Error on 27.5.1:

```
failed to create network algowiz_sandbox: Error response from daemon: failed to
parse com.docker.network.bridge.gateway_mode_ipv4 value: isolated (unknown
gateway mode isolated)
```

Old engines may ignore the option silently, so **no error does not prove the
network is isolated.** After the first start, run:

```bash
docker network inspect algowiz_sandbox -f '{{json .IPAM.Config}}'
```

The output must contain a `Subnet` and **no `Gateway`**. If there is a
`Gateway`, run `docker compose down` and upgrade Docker.
`tests/security_check.py` also fails in that case. Versions 25 and 26 were not
tested.

## What the containers limit

| Limit | Setting | How it was checked |
|---|---|---|
| Non-root user (UID 10001), not privileged | `user` | Docker's reported settings |
| No Linux capabilities | `cap_drop: ALL` | Kernel status in the container |
| No privilege gain through setuid programs | `no-new-privileges` | Kernel status in the container |
| System calls | Docker's default seccomp profile (no custom filter) | A filter is active |
| Read-only root filesystem; `/app` cannot be changed | `read_only` | Submitted code |
| Container memory 512 MB, no extra swap | `mem_limit`, `memswap_limit` | 700 MB allocation killed |
| 1 CPU | `cpus` | Docker's reported settings only |
| 128 processes and threads per container | `pids_limit` | Docker's reported settings only |
| Per process: 256 MB address space, 10 s CPU, 20 MB per file; 64 processes for the user | `sandboxed_worker.py` | Submitted code |
| No connection to the Docker host or the public internet | internal network, isolated gateway | Submitted code |
| 25 s per request; processes it started are killed afterwards | `sandbox_run.py` | Runaway loop, fork bomb, detached and fork-and-exit processes |

Docker's default seccomp profile allows the `ptrace` calls `gdb` needs, so no
extra permission is granted.

## What the containers do not limit

The Flask server and submitted code run as **the same user** in **the same
container**. This was a deliberate choice, to keep `cap-drop ALL`.

Reproduced by `tests/security_check.py`:

- **Submitted code can kill the server.** Docker restarts the container.
- **Submitted code can freeze the server** (`SIGSTOP`). Docker marks it
  unhealthy but does **not** restart it. Run `docker compose restart backend`.
- Submitted code can fill `/tmp`, which breaks later requests until a restart.
- Submitted code can read the server's source, and can write to `/tmp` and
  `/dev/shm`.
- Submitted code can connect to the proxy and to the backend's own API.
- While a fork bomb runs, other requests fail.

Also open (from the design, not exercised by a test):

- Submitted code shares the host's kernel. There is no gVisor or Firecracker.
- No request queue, rate limit or authentication.
- Any process of this user can interfere with another request that is running.
- The API accepts requests from any web origin (CORS), so a website you visit
  while the stack is running could send code to `localhost:5001`.
- Some error responses include a Python traceback.
- The 64-process limit counts per user ID, so other processes on the Docker host
  that use UID 10001 can count against it.
- The proxy can reach the internet; the backend cannot.

## What testing the container flags showed

Results of applying the flags to the **original code**, before any fix:

| Test | Result | Fix |
|---|---|---|
| `--cap-drop ALL`, running as root | Worker crashes at `os.setgroups` | Run as non-root |
| Running as non-root | **All resource limits silently skipped** (memory unlimited, process limit 32017) | Apply limits for non-root too |
| Default `--tmpfs /tmp` | Compiled program cannot execute; shows a misleading 25 s timeout | Mount it with `exec` |
| No `libc6-dbg` | `malloc` tracking silently disappears | Install it |
| Fork bomb, flags on | 127 processes left over; the next request could not start | Kill all descendants, add an init process |
| Outbound connect | `unshare` fails in the container, and submitted C **reached a service on the host** | Isolate the network |
| gdb / ptrace | Works under Docker's default seccomp profile, with one harmless address-randomisation warning | No extra permission needed |

Found while building the fixes:

| Test | Result | Fix |
|---|---|---|
| Resource limits on a machine with 4 or more CPUs (simulated) | `gdb` crashes: its worker threads do not fit in 256 MB. The original code does the same when run as root (tested with 8 and 16 threads) | `gdb` runs with no worker threads |
| First version of the cleanup, fork bomb | 62 processes left; the next request failed | Freeze all of them before killing any |
| `internal: true` without isolated gateway mode | Submitted C still reached the host | `gateway_mode_ipv4: isolated` |
| Docker 24.0.7 | Isolation option ignored without an error | Require 28.0; check the network (above) |

## Tests

Each is one command, run from the repository root:

```bash
docker compose run --rm --build tests    # pytest: recursion, malloc/free, compile error, timeout
python3 tests/security_check.py          # hostile programs against the running stack
python3 tests/behaviour_check.py         # traces match those of the pre-container code
```

`security_check.py` crashes and freezes the backend on purpose, and stops the
stack when it finishes. It prints `PASS`, `FAIL`, `GAP` (a known weakness,
reproduced) or `INCONCLUSIVE`. Exit code: 0 clean, 1 any failure, 2 something
inconclusive. Add `--report results.md` to save the results.

`behaviour_check.py` leaves the stack running. Its baseline,
`tests/baseline/unmodified.json`, was recorded from the unmodified code.

### Results

| | |
|---|---|
| Date | 2026-11-27 |
| Docker Engine / Compose | 29.9.3 / 5.7.1 |
| OS | Ubuntu 24.04.5 LTS, kernel 6.18.44-fc-v880, cgroup v1, 2 CPUs |
| In the image | gcc 13.3.0, gdb 15.1, Flask 3.1.3, pygdbmi 0.11.0.0, psutil 7.2.2 |
| pytest | 4 passed |
| Security checks | 48 PASS, 0 FAIL, 9 GAP, 1 INCONCLUSIVE (external DNS: the test machine had none to compare with) |
| Behaviour | normal, recursion and malloc/free traces unchanged |

**These images were not the Docker Hub ones.** Docker Hub was unreachable, so
`ubuntu:24.04` was assembled from the Ubuntu package archive, and an Ubuntu
nginx 1.24 image stood in for `nginxinc/nginx-unprivileged:stable-alpine`.
Re-run all three commands on your machine before quoting these results.

A pass covers only the cases tested. It does not make the backend fit for
untrusted users.

## CI

`.github/workflows/ci.yml`:

- **Build image and run pytest** runs on every push and pull request. To block
  merges on it, add it as a required status check in the repository's branch
  protection settings.
- **Security and behaviour checks (manual)** runs only from **Actions > CI >
  Run workflow**, because it has not yet been run on GitHub's runners.

## Without Docker

See [`pages/README.md`](pages/README.md). The container limits above do not
apply there.
