# Security check results

- Date: 2026-11-27 03:39 India Standard Time
- Docker Engine: 29.9.3
- Docker Compose: 5.7.1
- Docker host OS: Docker Desktop, kernel 5.15.167.4-microsoft-standard-WSL2, cgroup v1
- Docker security options: name=seccomp,profile=builtin
- Script ran on: Windows-10-10.0.26300-SP0

23 PASS, 6 FAIL, 3 GAP, 0 INCONCLUSIVE

| Result | Check | Detail |
|---|---|---|
| PASS | runs as non-root user 10001 | 10001:10001 |
| PASS | not privileged |  |
| PASS | root filesystem is read-only |  |
| PASS | all capabilities dropped |  |
| PASS | no-new-privileges set |  |
| PASS | no seccomp override (Docker's default profile) |  |
| PASS | pids limit 128 | 128 |
| PASS | memory limit 512 MB, no extra swap | 536870912 / 536870912 |
| PASS | CPU limit 1 |  |
| PASS | init process enabled |  |
| PASS | /tmp is a tmpfs |  |
| PASS | restart policy unless-stopped |  |
| PASS | kernel: no effective capabilities |  |
| PASS | kernel: NoNewPrivs = 1 |  |
| PASS | kernel: a seccomp filter is active |  |
| PASS | a 700 MB allocation inside the container is stopped | exit code 137 |
| PASS | server healthy afterwards |  |
| FAIL | nproc limit is 64 | got -1 |
| FAIL | memory limit is 268435456 | got -1 |
| FAIL | cpu limit is 10 | got -1 |
| FAIL | fsize limit is 20971520 | got -1 |
| FAIL | submitted code cannot allocate 256 MB | got 16 blocks of 64 MB |
| PASS | cannot create files in /app |  |
| PASS | cannot modify the server's code |  |
| GAP | can READ the server's source code |  |
| GAP | can write to /tmp (shared by all requests) |  |
| GAP | can write to /dev/shm |  |
| PASS | Runaway loop: the request gets an answer | 14.7s, ok=True, error=None, truncated=True |
| PASS | Runaway loop: no processes left behind |  |
| PASS | Runaway loop: a normal request still works afterwards |  |
| PASS | Fork bomb: the request gets an answer | 27.9s, ok=False, error=timeout, truncated=None |
| FAIL | the script could not finish | docker compose exec -T backend python3 -c import os for p in os.listdir('/proc'):     if p.isdigit() and int(p) not in (1, os.getpid()):         try:             cmd = open(f'/proc/{p}/cmdline','rb').read().replace(b'\0', b' ').decode().strip()             state = open(f'/proc/{p}/stat').read().rsplit(')', 1)[1].split()[0]         except OSError:             continue         if cmd != 'python3 app.py' and 'urlopen' not in cmd:             print(p, state, cmd or '(exited, not reaped)')  failed: OCI runtime exec failed: exec failed: unable to start container process: procReady not received   |
