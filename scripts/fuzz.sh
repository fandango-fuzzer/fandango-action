#!/usr/bin/env bash
# The action's fuzz step: `fanbase fuzz`, with the record encrypted to the given keys. It runs outside GitHub
# too: set the FUZZ_ variables (see action.yml), and the summary and outputs go to files in FUZZ_OUT.
set -euo pipefail

out="${FUZZ_OUT:?FUZZ_OUT is where the record and the counts go}"
mkdir -p "$out"
registry="$(cd "${FUZZ_REGISTRY:?FUZZ_REGISTRY is a Fanbase registry checkout}" && pwd)"
summary="${GITHUB_STEP_SUMMARY:-$out/step-summary.md}"
outputs="${GITHUB_OUTPUT:-$out/outputs.txt}"

# The keys: a public key is not a secret, but without one nothing found could be kept private, so nothing runs.
recipients="$out/recipients.txt"
if [ -n "${FUZZ_RECIPIENTS_FILE:-}" ]; then
  cp -- "$FUZZ_RECIPIENTS_FILE" "$recipients"
else
  printf '%s\n' "${FUZZ_RECIPIENTS:-}" > "$recipients"
fi
if ! grep -q '^[[:space:]]*age1' "$recipients"; then
  echo "::error::No age public key. Give the action \`recipients\` (age1...) or \`recipients-file\`: without one, what is found could not be kept private, so nothing is run."
  exit 2
fi

read -r -a specs <<< "${FUZZ_SPECS:?FUZZ_SPECS names the specs}"
args=(fuzz "${specs[@]}"
      -n "${FUZZ_COUNT:-200}" --seed "${FUZZ_SEED:-1}" --budget "${FUZZ_BUDGET:-300}" --timeout "${FUZZ_TIMEOUT:-10}"
      --reduce-budget "${FUZZ_REDUCE_BUDGET:-60}" --record "$out/record" --recipients "$recipients"
      --markdown --json-file "$out/counts.json")
# Only the program of this repository is fuzzed: its targets come from a folder inside the repository, each runs
# a harness of its own folder, and the registry's targets are never taken (--only-own-targets).
repository="$(cd "${GITHUB_WORKSPACE:-.}" && pwd -P)"
target_dir="${FUZZ_TARGET_DIR:-.fandango/targets}"
if [ ! -d "$target_dir" ]; then
  echo "::error::There is no $target_dir in the repository: nothing says how to run your program. See https://github.com/fandango-fuzzer/fandango-action#getting-started"
  exit 2
fi
target_dir="$(cd "$target_dir" && pwd -P)"
case "$target_dir/" in
  "$repository"/*) ;;
  *) echo "::error::target-dir has to be a folder of this repository; $FUZZ_TARGET_DIR is not"; exit 2 ;;
esac
args+=(--target-dir "$target_dir" --only-own-targets)
if [ -n "${FUZZ_TARGETS:-}" ]; then
  args+=(--targets "$FUZZ_TARGETS")
fi
case "${FUZZ_FAIL:-false}" in
  true) args+=(--fail) ;;
  false) ;;
  *) echo "::error::fail-on-findings is true or false, not ${FUZZ_FAIL}"; exit 2 ;;
esac

status=0
fanbase --registry "$registry" "${args[@]}" > "$out/counts.md" || status=$?
cat "$out/counts.md"
{
  cat "$out/counts.md"
  echo
  echo "The record of this run is encrypted to your key, in the artifact of this run. To read it:"
  echo
  echo '```'
  echo "fanbase incidents open fuzz-private.age --identity YOUR-AGE-KEY.txt --into fandango-record"
  echo '```'
} >> "$summary"

record="$out/record/fuzz-private.age"
if [ -f "$record" ]; then
  echo "record=$record" >> "$outputs"
fi
findings="$(python - "$out/counts.json" <<'PY' 2>/dev/null || true
import json, sys
print(json.load(open(sys.argv[1]))["findings"]["kinds"])
PY
)"
echo "findings=$findings" >> "$outputs"
exit "$status"
