"""Reads one file with the example project's reader: exit 0 if it reads it, else say why and exit 1."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # the project: example/

from jsonish import load  # noqa: E402

try:
    load(sys.argv[1])
except ValueError as exc:
    print(f"rejected: {exc}", file=sys.stderr)
    sys.exit(1)
