#!/usr/bin/env bash
# The action's fuzz step: `fanbase fuzz`, and what it found reported the way FUZZ_REPORT says: as code scanning
# alerts (a SARIF file, which the action uploads), or as a record encrypted to the given keys. It runs outside
# GitHub too: set the FUZZ_ variables (see action.yml), and the summary and outputs go to files in FUZZ_OUT.
set -euo pipefail

out="${FUZZ_OUT:?FUZZ_OUT is where the record and the counts go}"
mkdir -p "$out"
registry="$(cd "${FUZZ_REGISTRY:?FUZZ_REGISTRY is a Fanbase registry checkout}" && pwd)"
summary="${GITHUB_STEP_SUMMARY:-$out/step-summary.md}"
outputs="${GITHUB_OUTPUT:-$out/outputs.txt}"

# Where what is found goes. "alerts": code scanning alerts, which people with write access to the repository
# read in its Security tab, and nobody else. "record": a file encrypted to age keys, kept as an artifact.
# With nothing said, it is the record if a key is given (as before there were alerts), and else the alerts.
recipients="$out/recipients.txt"
if [ -n "${FUZZ_RECIPIENTS_FILE:-}" ]; then
  cp -- "$FUZZ_RECIPIENTS_FILE" "$recipients"
else
  printf '%s\n' "${FUZZ_RECIPIENTS:-}" > "$recipients"
fi
report="${FUZZ_REPORT:-}"
if [ -z "$report" ]; then
  if grep -q '[^[:space:]]' "$recipients"; then report=record; else report=alerts; fi
fi
case "$report" in
  alerts) ;;
  record)
    # A public key is not a secret, but without one nothing found could be kept private, so nothing runs.
    if ! grep -q '^[[:space:]]*age1' "$recipients"; then
      echo "::error::No age public key. With \`report: record\`, give the action \`recipients\` (age1...) or \`recipients-file\`: without one, what is found could not be kept private, so nothing is run."
      exit 2
    fi ;;
  *) echo "::error::report is alerts or record, not $report"; exit 2 ;;
esac

read -r -a specs <<< "${FUZZ_SPECS:?FUZZ_SPECS names the specs}"
args=(fuzz "${specs[@]}"
      -n "${FUZZ_COUNT:-200}" --seed "${FUZZ_SEED:-1}" --budget "${FUZZ_BUDGET:-300}" --timeout "${FUZZ_TIMEOUT:-10}"
      --reduce-budget "${FUZZ_REDUCE_BUDGET:-60}" --record "$out/record"
      --markdown --json-file "$out/counts.json")
if [ "$report" = record ]; then
  args+=(--recipients "$recipients")
fi
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
if [ "$report" = record ]; then
  fanbase --registry "$registry" "${args[@]}" > "$out/counts.md" || status=$?
else
  # Without keys fanbase writes the record in the clear, into a folder of the runner that nothing uploads, and
  # says where: its counts are for the log, the rest of what it says is not.
  fanbase --registry "$registry" "${args[@]}" > "$out/counts.md" 2> "$out/fanbase.log" || status=$?
  grep -E '^fuzzing with |^  [^ ]+: a kind of ' "$out/fanbase.log" >&2 || true
  if [ "$status" -ne 0 ] && [ ! -s "$out/counts.md" ]; then
    cat "$out/fanbase.log" >&2  # it did not get to fuzz: say why
  fi
fi
cat "$out/counts.md"

if [ "$report" = record ]; then
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
elif [ -s "$out/counts.md" ]; then
  # The alerts that are open are tried again, so that one is closed when its input is accepted, and not when
  # this run's inputs happen not to show it. Listing them needs the job's token and `security-events`.
  open="$out/open-alerts.jsonl"
  : > "$open"
  if [ -n "${GH_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ] && command -v gh > /dev/null; then
    gh api --paginate --jq '.[]' \
      "repos/$GITHUB_REPOSITORY/code-scanning/alerts?state=open&tool_name=Fandango&ref=${GITHUB_REF:-}&per_page=100" \
      > "$open" 2> /dev/null || : > "$open"  # no analysis yet, or no code scanning: there is none to try
  fi
  python "$(dirname "$0")/alerts.py" "$out/record" "$target_dir" "$out/fandango.sarif" \
    --open "$open" --shown-dir "${target_dir#"$repository"/}" --timeout "${FUZZ_TIMEOUT:-10}" | tee "$out/alerts.txt"
  echo "sarif=$out/fandango.sarif" >> "$outputs"
  {
    cat "$out/counts.md"
    echo
    cat "$out/alerts.txt"
    echo
    echo "What was found is in the Security tab of the repository, under Code scanning, where people with write access can read it:"
    echo "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-OWNER/REPOSITORY}/security/code-scanning?query=is%3Aopen+tool%3AFandango"
  } >> "$summary"
fi
findings="$(python - "$out/counts.json" <<'PY' 2>/dev/null || true
import json, sys
print(json.load(open(sys.argv[1]))["findings"]["kinds"])
PY
)"
echo "findings=$findings" >> "$outputs"
exit "$status"
