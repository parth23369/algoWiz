#!/usr/bin/env python3
"""
Checks that tracing behaviour matches the code as it was BEFORE containerising.

Sends three C programs (plain, recursion, malloc/free) to a running backend and
compares the traces with tests/baseline/unmodified.json, which was recorded from
the unmodified code.

    python3 tests/behaviour_check.py                 # start the stack, then compare
    python3 tests/behaviour_check.py --url URL       # compare against a running backend
    python3 tests/behaviour_check.py --save FILE     # record a new baseline

Two things differ between any two runs, so they are normalised before comparing:
  * memory addresses become ADDR1, ADDR2, ... in order of first appearance
  * a local is shown as UNSET until execution has moved past the line that
    declares it (before that, its value is leftover stack memory)

Standard library only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline", "unmodified.json")

# name -> (source, {local name: line number that declares it})
CASES = {
    "normal": (
        """#include <stdio.h>

int main() {
    int a = 5;
    int b = 10;
    int sum = a + b;
    printf("%d\\n", sum);
    return 0;
}
""",
        {"a": 4, "b": 5, "sum": 6},
    ),
    "recursion": (
        """#include <stdio.h>

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main() {
    int result = factorial(4);
    printf("%d\\n", result);
    return 0;
}
""",
        {"result": 9},
    ),
    "malloc": (
        """#include <stdio.h>
#include <stdlib.h>

int main() {
    int *arr = malloc(3 * sizeof(int));
    arr[0] = 1;
    arr[1] = 2;
    arr[2] = 3;
    int total = arr[0] + arr[1] + arr[2];
    free(arr);
    printf("%d\\n", total);
    return 0;
}
""",
        {"arr": 5, "total": 9},
    ),
}


def run_case(url, source):
    request = urllib.request.Request(
        url.rstrip("/") + "/run",
        data=json.dumps({"code": source}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def normalise(result, declared_at):
    result = json.loads(json.dumps(result))  # deep copy
    for step in result.get("steps", []):
        for frame in step["stack"]:
            for name in frame["locals"]:
                if name in declared_at and (frame["line"] or 0) <= declared_at[name]:
                    frame["locals"][name] = "UNSET"

    seen = {}

    def rename(match):
        address = match.group(0)
        if int(address, 16) == 0:
            return address
        return seen.setdefault(address, f"ADDR{len(seen) + 1}")

    return json.loads(re.sub(r"0x[0-9a-fA-F]+", rename, json.dumps(result)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="use a running backend instead of starting the stack")
    parser.add_argument("--save", help="write a baseline file instead of comparing")
    args = parser.parse_args()

    if args.url is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if subprocess.run(["docker", "compose", "up", "-d", "--build", "--wait"], cwd=root).returncode:
            print("Could not start the stack.")
            return 2
        args.url = "http://localhost:5001"

    try:
        raw = {name: run_case(args.url, source) for name, (source, _) in CASES.items()}
    except (urllib.error.URLError, OSError) as error:
        print(f"Cannot reach the backend at {args.url}: {error}")
        return 2

    current = {name: normalise(raw[name], CASES[name][1]) for name in CASES}

    if args.save:
        os.makedirs(os.path.dirname(os.path.abspath(args.save)), exist_ok=True)
        with open(args.save, "w") as handle:
            json.dump({"normalised": current, "raw": raw}, handle, indent=1)
        for name, result in current.items():
            print(f"saved {name}: ok={result.get('ok')} steps={len(result.get('steps', []))}")
        return 0

    with open(BASELINE) as handle:
        baseline = json.load(handle)["normalised"]

    failures = 0
    for name in CASES:
        same = current[name] == baseline[name]
        failures += not same
        print(f"{'PASS' if same else 'FAIL'}  {name}: {len(current[name].get('steps', []))} steps "
              f"(baseline {len(baseline[name].get('steps', []))})")
        if not same:
            before = baseline[name].get("steps", [])
            after = current[name].get("steps", [])
            for index, (old, new) in enumerate(zip(before, after)):
                if old != new:
                    print(f"      first difference at step {index}:\n      before: {old}\n      after:  {new}")
                    break
            else:
                print(f"      before: {str(baseline[name])[:300]}\n      after:  {str(current[name])[:300]}")
    print("Behaviour unchanged." if not failures else f"{failures} case(s) differ.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())