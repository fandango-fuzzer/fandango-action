#!/usr/bin/env bash
# The action's install step: age (to encrypt the record), Fandango and fanbase, into the Python on the PATH.
set -euo pipefail

if ! command -v age > /dev/null; then
  if command -v apt-get > /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq --no-install-recommends age > /dev/null
  elif command -v brew > /dev/null; then
    brew install --quiet age
  else
    echo "::error::age is needed to encrypt the record, and there is no apt-get or brew to install it with"
    exit 1
  fi
fi

python -m pip install --quiet --disable-pip-version-check "${FANDANGO:?}" "${FANBASE:?}"
echo "Fandango $(python -c 'import importlib.metadata as m; print(m.version("fandango-fuzzer"))'), $(fanbase --version), $(age --version | head -1)"
