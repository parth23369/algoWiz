"""
Tests for the C tracer, run through the same entry point the API uses.

    docker compose run --rm --build tests

They need Linux, gcc, gdb and libc debug symbols, so run them in the container.
"""

import os
import sys
import time

import psutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# In the repository the backend lives in pages/; in the image it is in /app.
BACKEND_DIR = os.path.join(ROOT, "pages")
sys.path.insert(0, BACKEND_DIR if os.path.isdir(BACKEND_DIR) else ROOT)

import sandbox_run  # noqa: E402

RECURSION = """int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main() {
    int result = factorial(4);
    return 0;
}
"""

HEAP = """#include <stdlib.h>

int main() {
    int *arr = malloc(3 * sizeof(int));
    arr[0] = 1;
    free(arr);
    return 0;
}
"""

SLEEPER = """#include <unistd.h>

int main() {
    sleep(60);
    return 0;
}
"""


def trace_ok(source):
    result = sandbox_run.run_sandboxed(source)
    assert result["ok"], result
    assert result["truncated"] is False
    return result["steps"]


def test_recursion():
    steps = trace_ok(RECURSION)

    stacks = [[f for f in step["stack"] if f["func"] == "factorial"] for step in steps]
    deepest = max(stacks, key=len)
    # Innermost frame first.
    assert [frame["locals"]["n"] for frame in deepest] == ["1", "2", "3", "4"]

    last_frame = steps[-1]["stack"][0]
    assert last_frame["func"] == "main"
    assert last_frame["locals"]["result"] == "24"


def test_malloc_and_free():
    steps = trace_ok(HEAP)

    allocations = [s for s in steps if s["message"].startswith("malloc(")]
    assert len(allocations) == 1, [s["message"] for s in steps]
    block = allocations[0]["heap"]
    assert len(block) == 1 and block[0]["size"] == 12
    address = block[0]["addr"]
    assert allocations[0]["message"] == f"malloc(12) -> {address}"

    frees = [s for s in steps if s["message"].startswith("free(")]
    assert [s["message"] for s in frees] == [f"free({address})"]
    assert frees[0]["heap"] == []
    assert steps[-1]["heap"] == []


def test_compile_error():
    result = sandbox_run.run_sandboxed("int main() { return missing; }")

    assert result["ok"] is False
    assert result["error"] == "compile_error"
    assert "missing" in result["detail"]


def test_timeout(monkeypatch):
    monkeypatch.setattr(sandbox_run, "OVERALL_TIMEOUT_SEC", 2)
    started = time.monotonic()

    result = sandbox_run.run_sandboxed(SLEEPER)

    assert result["ok"] is False
    assert result["error"] == "timeout"
    assert time.monotonic() - started < 15
    # Nothing from the timed-out request is left running.
    assert psutil.Process().children(recursive=True) == []

    # The next request still works.
    monkeypatch.undo()
    trace_ok(RECURSION)