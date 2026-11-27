#!/usr/bin/env python3
"""
Runs hostile C programs against the running containers and reports what the
limits stop and what they do not.

    python3 tests/security_check.py

It builds and starts the compose stack, runs every check, restarts the backend
where a check breaks it, and stops the stack afterwards. Run it from anywhere;
it needs Docker and Python 3 on the host, nothing else. It takes a few minutes.

Do not run it while you are using the app: it crashes and freezes the backend
on purpose.

Result labels:
  PASS          the limit behaved as described
  FAIL          it did not
  GAP           a known weakness, reproduced (expected; not a test failure)
  INCONCLUSIVE  the check could not prove anything on this machine

Exit code: 0 = no FAIL and nothing INCONCLUSIVE, 1 = at least one FAIL,
2 = no FAIL but something INCONCLUSIVE.

Passing does not mean the setup is safe for untrusted users. It covers only
the cases below.
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
URL = "http://localhost:5001"
LISTENER = "algowiz-check-listener"
LISTENER_PORT = 47821
RESULTS = []


# ── helpers ──────────────────────────────────────────────────────────────────

def sh(*cmd, check=True, timeout=900):
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          errors="replace", timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc


def compose(*args, **kwargs):
    return sh("docker", "compose", *args, **kwargs)


def inspect(target, kind="container"):
    return json.loads(sh("docker", kind, "inspect", target).stdout)[0]


def record(status, name, detail=""):
    RESULTS.append((status, name, detail))
    print(f"  {status:<13} {name}" + (f"  [{detail}]" if detail else ""), flush=True)


def expect(condition, name, detail=""):
    record("PASS" if condition else "FAIL", name, detail)


def submit(code, timeout=45):
    request = urllib.request.Request(
        URL + "/run", data=json.dumps({"code": code}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        try:
            return json.load(error)
        except ValueError:
            return {"ok": False, "error": "http", "detail": f"HTTP {error.code}"}
    except Exception as error:  # dropped connection, client timeout, ...
        return {"ok": False, "error": "http", "detail": f"{type(error).__name__}: {error}"}


def healthy():
    try:
        with urllib.request.urlopen(URL + "/health", timeout=4) as response:
            return response.status == 200
    except Exception:
        return False


def wait_healthy(seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if healthy():
            return True
        time.sleep(1)
    return False


def wait_health_status(container, wanted, seconds=90):
    """Wait for Docker's own health status; returns the last status seen."""
    deadline = time.time() + seconds
    while True:
        status = inspect(container)["State"].get("Health", {}).get("Status")
        if status == wanted or time.time() > deadline:
            return status
        time.sleep(2)


def restart_backend():
    compose("restart", "backend")
    if not wait_healthy():
        raise RuntimeError("backend did not come back after a restart")


def locals_of_main(result):
    """Locals of main() at the last recorded step."""
    for step in reversed(result.get("steps", [])):
        for frame in step["stack"]:
            if frame["func"] == "main" and frame["is_user_code"]:
                return frame["locals"]
    return {}


def number(values, name):
    try:
        return int(str(values.get(name)).split()[0])
    except (ValueError, IndexError):
        return None


def probe(code, *names):
    """Run a probe program and read integer locals of main(). Returns None if
    the program did not run to the end, so a broken probe cannot pass."""
    result = submit(code)
    values = locals_of_main(result)
    numbers = {name: number(values, name) for name in names + ("done",)}
    if not result.get("ok") or numbers["done"] != 1:
        print(f"    probe did not complete: {str(result)[:300]}")
        return None
    return numbers


def leftovers():
    """Processes in the backend container other than init, the server, the
    health check and this listing."""
    script = (
        "import os\n"
        "for p in os.listdir('/proc'):\n"
        "    if p.isdigit() and int(p) not in (1, os.getpid()):\n"
        "        try:\n"
        "            cmd = open(f'/proc/{p}/cmdline','rb').read().replace(b'\\0', b' ').decode().strip()\n"
        "            state = open(f'/proc/{p}/stat').read().rsplit(')', 1)[1].split()[0]\n"
        "        except OSError:\n"
        "            continue\n"
        "        if cmd != 'python3 app.py' and 'urlopen' not in cmd:\n"
        "            print(p, state, cmd or '(exited, not reaped)')\n"
    )
    out = compose("exec", "-T", "backend", "python3", "-c", script).stdout
    # A finished health check can show up for an instant with an empty cmdline.
    return [line for line in out.splitlines() if line.strip()]


def settled_leftovers():
    found = []
    for _ in range(4):
        time.sleep(1.5)
        found = leftovers()
        if not found:
            break
    return found


NORMAL = "int main() {\n    int x = 41;\n    x++;\n    return 0;\n}\n"


def server_still_works(label):
    result = submit(NORMAL)
    expect(result.get("ok") and locals_of_main(result).get("x") == "42",
           f"{label}: a normal request still works afterwards",
           "" if result.get("ok") else str(result)[:200])


# ── checks ───────────────────────────────────────────────────────────────────

def check_configuration(backend):
    print("\nContainer settings (what Docker reports for the running backend)")
    info = inspect(backend)
    host, config = info["HostConfig"], info["Config"]
    options = host.get("SecurityOpt") or []
    expect(config["User"] == "10001:10001", "runs as non-root user 10001", config["User"])
    expect(not host["Privileged"], "not privileged")
    expect(host["ReadonlyRootfs"], "root filesystem is read-only")
    expect(host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"), "all capabilities dropped")
    expect(any(o.startswith("no-new-privileges") for o in options), "no-new-privileges set")
    expect(not any(o.startswith("seccomp") for o in options),
           "no seccomp override (Docker's default profile)")
    expect(host["PidsLimit"] == 128, "pids limit 128", str(host["PidsLimit"]))
    expect(host["Memory"] == host["MemorySwap"] == 512 * 1024 * 1024, "memory limit 512 MB, no extra swap",
           f"{host['Memory']} / {host['MemorySwap']}")
    expect(host["NanoCpus"] == 1_000_000_000, "CPU limit 1")
    expect(host.get("Init") is True, "init process enabled")
    expect("exec" in host.get("Tmpfs", {}).get("/tmp", ""), "/tmp is a tmpfs")
    expect(host["RestartPolicy"]["Name"] == "unless-stopped", "restart policy unless-stopped")

    status = compose("exec", "-T", "backend", "cat", "/proc/1/status").stdout
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    expect(int(fields["CapEff"], 16) == 0, "kernel: no effective capabilities")
    expect(fields["NoNewPrivs"].strip() == "1", "kernel: NoNewPrivs = 1")
    expect(fields["Seccomp"].strip() == "2", "kernel: a seccomp filter is active")


def check_memory_limit():
    print("\nContainer memory limit")
    proc = compose("exec", "-T", "backend", "python3", "-c",
                   "x = bytearray(700 * 1024 * 1024); print('allocated')", check=False)
    expect(proc.returncode != 0 and "allocated" not in proc.stdout,
           "a 700 MB allocation inside the container is stopped", f"exit code {proc.returncode}")
    expect(wait_healthy(), "server healthy afterwards")


def check_resource_limits():
    print("\nPer-process limits seen by submitted code")
    values = probe("""#include <sys/resource.h>

int main() {
    struct rlimit r;
    getrlimit(RLIMIT_NPROC, &r);
    long nproc = r.rlim_cur;
    getrlimit(RLIMIT_AS, &r);
    long memory = r.rlim_cur;
    getrlimit(RLIMIT_CPU, &r);
    long cpu = r.rlim_cur;
    getrlimit(RLIMIT_FSIZE, &r);
    long fsize = r.rlim_cur;
    int done = 1;
    return 0;
}
""", "nproc", "memory", "cpu", "fsize")
    wanted = {"nproc": 64, "memory": 256 << 20, "cpu": 10, "fsize": 20 << 20}
    for name, value in wanted.items():
        got = values and values[name]
        expect(got == value, f"{name} limit is {value}", f"got {got}")

    values = probe("""#include <stdlib.h>

int main() {
    int blocks = 0;
    while (blocks < 16 && malloc(64 << 20) != NULL)
        blocks++;
    int done = 1;
    return 0;
}
""", "blocks")
    expect(values is not None and values["blocks"] < 4, "submitted code cannot allocate 256 MB",
           f"got {values and values['blocks']} blocks of 64 MB")


def check_filesystem():
    print("\nFilesystem, from submitted code")
    values = probe("""#include <fcntl.h>
#include <unistd.h>

int main() {
    int app_new = open("/app/probe", O_WRONLY | O_CREAT, 0644);
    int app_edit = open("/app/app.py", O_WRONLY | O_APPEND);
    int app_read = open("/app/app.py", O_RDONLY);
    int tmp_new = open("/tmp/probe", O_WRONLY | O_CREAT, 0644);
    int shm_new = open("/dev/shm/probe", O_WRONLY | O_CREAT, 0644);
    unlink("/tmp/probe");
    unlink("/dev/shm/probe");
    int done = 1;
    return 0;
}
""", "app_new", "app_edit", "app_read", "tmp_new", "shm_new")
    if values is None:
        record("FAIL", "filesystem probe did not run")
        return
    expect(values["app_new"] < 0, "cannot create files in /app")
    expect(values["app_edit"] < 0, "cannot modify the server's code")
    for name, text in (("app_read", "can READ the server's source code"),
                       ("tmp_new", "can write to /tmp (shared by all requests)"),
                       ("shm_new", "can write to /dev/shm")):
        record("GAP" if values[name] >= 0 else "PASS", text if values[name] >= 0 else f"blocked: {text}")


def check_process_abuse():
    cases = [
        ("Runaway loop", "int main() {\n    volatile int i = 0;\n    while (1) { i++; }\n    return 0;\n}\n"),
        ("Fork bomb", "#include <unistd.h>\n\nint main() {\n    while (1) { fork(); }\n    return 0;\n}\n"),
        ("Detached background process", """#include <unistd.h>

int main() {
    if (fork() == 0) {
        setsid();
        if (fork() == 0) {
            sleep(300);
        }
        _exit(0);
    }
    sleep(1);
    return 0;
}
"""),
        ("Fork-and-exit chain", """#include <unistd.h>

int main() {
    if (fork() == 0) {
        setsid();
        while (1) {
            if (fork() != 0) _exit(0);
        }
    }
    sleep(1);
    return 0;
}
"""),
    ]
    for label, code in cases:
        print(f"\n{label}")
        started = time.time()
        result = submit(code)
        elapsed = time.time() - started
        expect(result.get("error") != "http" and elapsed < 40,
               f"{label}: the request gets an answer", f"{elapsed:.1f}s, ok={result.get('ok')}, "
               f"error={result.get('error')}, truncated={result.get('truncated')}")
        found = settled_leftovers()
        expect(not found, f"{label}: no processes left behind",
               f"{len(found)} left, e.g. {found[:3]}" if found else "")
        server_still_works(label)
        if found:
            restart_backend()


def connect_program(ip, port):
    return f"""#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

int main() {{
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in a = {{0}};
    a.sin_family = AF_INET;
    a.sin_port = htons({port});
    inet_pton(AF_INET, "{ip}", &a.sin_addr);
    int rc = connect(s, (struct sockaddr *)&a, sizeof a);
    int pending = rc != 0 && errno == EINPROGRESS;
    int connected = rc == 0;
    if (pending) {{
        struct pollfd p = {{s, POLLOUT, 0}};
        int error = -1;
        socklen_t size = sizeof error;
        if (poll(&p, 1, 3000) == 1) getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &size);
        connected = error == 0;
    }}
    int done = 1;
    return 0;
}}
"""


def submitted_code_connects(ip, port):
    values = probe(connect_program(ip, port), "connected")
    return None if values is None else values["connected"] == 1


def default_network_connects(ip, port):
    """Positive control: the same connection from an ordinary container."""
    script = f"import socket; socket.create_connection(('{ip}', {port}), 4).close()"
    return sh("docker", "run", "--rm", "--entrypoint", "python3", "algowiz-backend",
              "-c", script, check=False, timeout=60).returncode == 0


def check_network(backend, proxy):
    print("\nNetwork")
    network = inspect("algowiz_sandbox", "network")
    gateways = [c.get("Gateway") for c in network["IPAM"]["Config"] if c.get("Gateway")]
    expect(network["Internal"], "backend network is internal")
    expect(network["Options"].get("com.docker.network.bridge.gateway_mode_ipv4") == "isolated"
           and not gateways, "backend network has no host address (isolated gateway mode)",
           f"gateway: {gateways}" if gateways else "")
    expect(list(inspect(backend)["NetworkSettings"]["Networks"]) == ["algowiz_sandbox"],
           "backend is attached to that network only")

    # A throwaway listener on the Docker host.
    sh("docker", "rm", "-f", LISTENER, check=False)
    server = ("import socket\n"
              "s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
              f"s.bind(('0.0.0.0', {LISTENER_PORT})); s.listen(20)\n"
              "while True:\n"
              "    c, a = s.accept(); print('accepted', a[0], flush=True); c.close()\n")
    sh("docker", "run", "-d", "--name", LISTENER, "--network", "host",
       "--entrypoint", "python3", "algowiz-backend", "-c", server)
    try:
        time.sleep(2)
        bridge = inspect("bridge", "network")["IPAM"]["Config"][0]
        host_ip = bridge.get("Gateway") or bridge["Subnet"].split("/")[0].rsplit(".", 1)[0] + ".1"
        listener_ok = default_network_connects(host_ip, LISTENER_PORT)

        subnet_first = network["IPAM"]["Config"][0]["Subnet"].split("/")[0].rsplit(".", 1)[0] + ".1"
        edge = inspect("algowiz_edge", "network")["IPAM"]["Config"][0].get("Gateway")
        targets = [("Docker host, default bridge address", host_ip),
                   ("Docker host, first address of the backend's own subnet", subnet_first)]
        if edge:
            targets.append(("Docker host, proxy network address", edge))
        for label, ip in targets:
            connected = submitted_code_connects(ip, LISTENER_PORT)
            if connected is None:
                record("FAIL", f"{label}: probe did not run")
            elif connected:
                record("FAIL", f"{label}: submitted code CONNECTED", ip)
            elif listener_ok:
                record("PASS", f"{label}: blocked", ip)
            else:
                record("INCONCLUSIVE", f"{label}: blocked, but the control could not reach the listener either", ip)

        connected = submitted_code_connects("1.1.1.1", 443)
        control = default_network_connects("1.1.1.1", 443)
        if connected is None:
            record("FAIL", "public internet: probe did not run")
        elif connected:
            record("FAIL", "public internet: submitted code CONNECTED to 1.1.1.1:443")
        elif control:
            record("PASS", "public internet (1.1.1.1:443): blocked; an ordinary container can reach it")
        else:
            record("INCONCLUSIVE", "public internet: blocked, but an ordinary container cannot reach it either")
    finally:
        sh("docker", "rm", "-f", LISTENER, check=False)

    values = probe("""#include <netdb.h>
#include <stddef.h>

int main() {
    struct addrinfo *found = NULL;
    int rc = getaddrinfo("example.com", "443", NULL, &found);
    int resolved = rc == 0;
    int done = 1;
    return 0;
}
""", "resolved")
    control = sh("docker", "run", "--rm", "--entrypoint", "python3", "algowiz-backend", "-c",
                 "import socket; socket.getaddrinfo('example.com', 443)", check=False).returncode == 0
    if values is None:
        record("FAIL", "external DNS: probe did not run")
    elif values["resolved"]:
        record("FAIL", "external DNS: submitted code resolved example.com")
    elif control:
        record("PASS", "external DNS: blocked; an ordinary container can resolve")
    else:
        record("INCONCLUSIVE", "external DNS: blocked, but an ordinary container cannot resolve either")

    # Things the network setup does NOT block.
    proxy_ip = inspect(proxy)["NetworkSettings"]["Networks"]["algowiz_sandbox"]["IPAddress"]
    for label, ip, port in (("the proxy container", proxy_ip, 8080),
                            ("the backend's own API on localhost", "127.0.0.1", 5001)):
        connected = submitted_code_connects(ip, port)
        if connected is None:
            record("FAIL", f"{label}: probe did not run")
        else:
            record("GAP" if connected else "PASS",
                   f"submitted code {'can' if connected else 'cannot'} connect to {label}")


def check_known_gaps(backend):
    print("\nKnown gaps (these restart the backend)")

    bomb = "#include <unistd.h>\n\nint main() {\n    while (1) { fork(); }\n    return 0;\n}\n"
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        running = pool.submit(submit, bomb)
        time.sleep(5)
        other = submit(NORMAL)
        running.result()
    if other.get("ok"):
        record("PASS", "another request succeeded while a fork bomb was running")
    else:
        record("GAP", "while a fork bomb runs, other requests fail", str(other.get("detail"))[:100])
    server_still_works("after the fork bomb ends")

    submit("""#include <fcntl.h>
#include <stdio.h>
#include <sys/statvfs.h>
#include <unistd.h>

int main() {
    char path[32];
    struct statvfs fs;
    for (int i = 0; i < 6; i++) {
        statvfs("/tmp", &fs);
        long size = fs.f_bavail * fs.f_frsize;
        if (size > (19 << 20)) size = 19 << 20;
        sprintf(path, "/tmp/fill_%d", i);
        int fd = open(path, O_WRONLY | O_CREAT, 0644);
        posix_fallocate(fd, 0, size);
        close(fd);
    }
    return 0;
}
""")
    after = submit(NORMAL)
    if after.get("ok") and after.get("steps"):
        record("PASS", "filling /tmp did not break later requests")
    else:
        record("GAP", "submitted code can fill /tmp and break later requests until a restart",
               str(after.get("detail"))[:100])
    restart_backend()
    server_still_works("after restarting")

    before = inspect(backend)["RestartCount"]
    submit("#include <signal.h>\n\nint main() {\n    kill(-1, SIGKILL);\n    return 0;\n}\n")
    time.sleep(3)
    recovered = wait_healthy()
    restarts = inspect(backend)["RestartCount"] - before
    if restarts > 0:
        record("GAP", "submitted code can KILL the server", f"Docker restarted it {restarts} time(s)")
        expect(recovered, "the server comes back on its own after being killed")
        server_still_works("after the automatic restart")
    else:
        record("PASS", "kill(-1) did not restart the server")

    wait_health_status(backend, "healthy")
    before = inspect(backend)["RestartCount"]
    submit("#include <signal.h>\n\nint main() {\n    kill(-1, SIGSTOP);\n    return 0;\n}\n", timeout=10)
    status = wait_health_status(backend, "unhealthy")
    state = inspect(backend)
    if not healthy() and state["RestartCount"] == before:
        record("GAP", "submitted code can FREEZE the server; Docker does not restart it",
               f"Docker health: {status}, restarts: 0")
    else:
        record("PASS", "the server recovered from kill(-1, SIGSTOP) without help")
    restart_backend()
    server_still_works("after a manual restart")


# ── main ─────────────────────────────────────────────────────────────────────

def environment():
    info = json.loads(sh("docker", "info", "--format", "{{json .}}").stdout)
    return {
        "Date": datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
        "Docker Engine": info["ServerVersion"],
        "Docker Compose": compose("version", "--short").stdout.strip(),
        "Docker host OS": f"{info['OperatingSystem']}, kernel {info['KernelVersion']}, "
                          f"cgroup v{info.get('CgroupVersion', '?')}",
        "Docker security options": ", ".join(info.get("SecurityOptions") or []),
        "Script ran on": platform.platform(),
    }


def main():
    parser = argparse.ArgumentParser(description="Security checks for the algoWiz containers.")
    parser.add_argument("--keep", action="store_true", help="leave the stack running afterwards")
    parser.add_argument("--report", help="also write the results to this Markdown file")
    args = parser.parse_args()

    env = environment()
    for key, value in env.items():
        print(f"{key}: {value}")

    try:
        print("\nBuilding and starting the stack ...", flush=True)
        compose("up", "-d", "--build", "--wait")
        backend = compose("ps", "-q", "backend").stdout.strip()
        proxy = compose("ps", "-q", "proxy").stdout.strip()

        check_configuration(backend)
        check_memory_limit()
        check_resource_limits()
        check_filesystem()
        check_process_abuse()
        check_network(backend, proxy)
        check_known_gaps(backend)
    except Exception as error:
        record("FAIL", "the script could not finish", str(error)[:600])
    finally:
        if not args.keep:
            compose("down", check=False)

    counts = {s: sum(r[0] == s for r in RESULTS) for s in ("PASS", "FAIL", "GAP", "INCONCLUSIVE")}
    summary = ", ".join(f"{count} {status}" for status, count in counts.items())
    print(f"\nSummary: {summary}")

    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write("# Security check results\n\n")
            handle.writelines(f"- {key}: {value}\n" for key, value in env.items())
            handle.write(f"\n{summary}\n\n| Result | Check | Detail |\n|---|---|---|\n")
            handle.writelines(f"| {s} | {n} | {d.replace('|', '/').replace(chr(10), ' ')} |\n"
                              for s, n, d in RESULTS)

    return 1 if counts["FAIL"] else 2 if counts["INCONCLUSIVE"] else 0


if __name__ == "__main__":
    sys.exit(main())