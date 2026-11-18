"""A small JSON reader with two bugs in it on purpose, for the action to find: the example project of this
repository, fuzzed by its own test (.github/workflows/test.yml), the way a real project fuzzes itself."""

import json
import os
import signal
import sys

# On a Mac, a process that dies of SIGSEGV brings up "Python quit unexpectedly" and leaves a crash report
# behind, every time; SIGTERM counts as a crash just the same, without either.
CRASH = signal.SIGTERM if sys.platform == "darwin" else signal.SIGSEGV


def _depth(value) -> int:
    if isinstance(value, dict):
        return 1 + max(map(_depth, value.values()), default=0)
    if isinstance(value, list):
        return 1 + max(map(_depth, value), default=0)
    return 0


def _no_exponent(text: str) -> float:
    raise ValueError(f"numbers with an exponent are not supported: {text}")  # bug 1: they are valid JSON


def load(path: str):
    with open(path, "rb") as file:
        value = json.loads(file.read(), parse_float=lambda t: _no_exponent(t) if "e" in t.lower() else float(t))
    if _depth(value) >= 5:
        os.kill(os.getpid(), CRASH)  # bug 2: what a stack overflow in C looks like
    return value
