"""Turn what `fanbase fuzz` found into code scanning alerts: a SARIF file for the Security tab.

Each kind of finding becomes one alert, which holds the reduced input and what the program said. Only
people with write access to the repository can read code scanning alerts, so nothing needs a key.

A new analysis replaces the last one, and an alert that is not in it is closed as fixed. The inputs of
a run are random, so a bug may simply not show this time. That is why the alerts that are open are
tried again first (their input is kept in the alert): one stays open until its input is accepted.

    python alerts.py RECORD_DIR TARGET_DIR OUT.sarif [--open ALERTS.json] [--timeout SECONDS]
"""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = "Fandango"
KEPT = 4_096  # an input up to this many bytes is kept in its alert, so that it can be tried again
SHOWN = 2_000  # and this much of it is shown
TRAILER = "fandango-alert: "  # the last line of an alert's text: what is needed to try it again
BROKE = {"crash": "crashes", "hang": "hangs", "killed": "is killed for what it uses"}
LEVEL = {"rejected": "warning", "disagreement": "warning"}


def normalise(why: str) -> str:
    """What a program said, without what changes from one input to the next: the class of the error."""
    why = re.sub(r"\{.*|\\n.*", "", why.replace('b"', ""))  # a dump of names, a second line
    why = re.sub(r'"[^"]*"|\'[^\']*\'|`[^`]*`', "…", why)
    # names and numbers of this input, but not the name of an error (Z3Exception)
    why = re.sub(r"\b(?!\w*(?:Error|Exception)\b)\w*\d\w*\b", "…", why)
    why = re.sub(r"(input|at|near|got|found|line|column|offset)\b:? .*", r"\1 …", why, flags=re.I)
    why = re.sub(r"(…[\s,.;:]*)+", "… ", why)
    return " ".join(why.split())[:90].rstrip(" :,;") or "rejected"


def show(data: bytes) -> str:
    cut = data[:SHOWN]
    try:
        text = cut.decode("utf-8")
        if any(ord(c) < ord(" ") and c not in "\n\t\r" for c in text):
            raise ValueError
    except ValueError:
        text = cut.hex(" ", 1)
    return text + (f"\n... ({len(data) - SHOWN} more bytes)" if len(data) > SHOWN else "")


def result(kind: str, spec: str, said: list[tuple[str, str]], accepted: list[str], data: bytes | None,
           target_dir: str, note: str = "") -> dict:
    """One alert. `said` is what each program that did not accept the input said."""
    targets = [t for t, _ in said]
    classes = [(t, normalise(w) if kind in LEVEL else BROKE.get(kind, kind)) for t, w in said]
    title = "; ".join(f"{t}: {c}" for t, c in classes)[:160]
    key = "|".join([kind, *sorted(f"{t}:{c}" for t, c in classes)])
    print_ = hashlib.sha256(key.encode()).hexdigest()[:16]
    if kind == "disagreement":
        head = f"{', '.join(targets)} reject a valid {spec} input that {', '.join(accepted)} accept."
    elif kind in LEVEL:
        head = f"{targets[0]} rejects a valid {spec} input."
    else:
        head = f"{targets[0]} {BROKE.get(kind, kind)} on a {spec} input."
    lines = [head, "", *[f"{t}: {w}" for t, w in said if w]]
    again = {"v": 1, "kind": kind, "spec": spec, "targets": targets, "accepted": accepted, "title": title}
    if data is not None:
        lines += ["", f"The input ({len(data)} bytes){note}:", "", show(data)]
        if len(data) <= KEPT:
            again["input"] = base64.b64encode(data).decode()
    lines += ["", TRAILER + json.dumps(again, separators=(",", ":"))]
    return {"ruleId": f"{kind}/{print_}", "level": LEVEL.get(kind, "error"), "title": title,
            "message": {"text": "\n".join(lines)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f"{target_dir}/{targets[0]}/target.yml"},
                "region": {"startLine": 1}}}],
            "partialFingerprints": {"fandangoFinding/v1": print_}}


def from_record(record: Path, target_dir: str) -> list[dict]:
    """The alerts of this run's record (the folder `fanbase fuzz --record` wrote)."""
    if not (record / "manifest.json").exists():  # fanbase writes it into a folder of its own
        inside = sorted(record.glob("*/manifest.json"))
        if not inside:
            return []  # nothing was found, so no record was written
        record = inside[0].parent
    manifest = json.loads((record / "manifest.json").read_text())
    results = []
    for finding in manifest.get("findings", []):
        said = [(t, why) for t, answer, why in finding["answers"] if answer != "accepted"]
        accepted = [t for t, answer, _ in finding["answers"] if answer == "accepted"]
        reduced = sorted((record / "findings" / finding["id"]).glob("reduced.*"))
        data = reduced[0].read_bytes() if reduced else None
        note = f", reduced, as {finding.get('inputs', 1)} input(s) of this run"
        results.append(result(finding["kind"], finding["spec"], said, accepted, data, target_dir, note))
    for incident in manifest.get("incidents", []):
        inputs = [record / i["file"] for i in incident.get("inputs", []) if (record / i["file"]).exists()]
        data = min((p.read_bytes() for p in inputs), key=len, default=None)
        stderr = record / incident["id"] / "stderr.txt"
        said = stderr.read_text(errors="replace").strip()[-600:] if stderr.exists() else ""
        how = incident.get("signal") or f"exit status {incident.get('returncode')}"
        note = f", the smallest of {incident.get('occurrences', 1)}"
        results.append(result(incident["kind"], incident["spec"], [(incident["target"], f"{how}. {said}")],
                              [], data, target_dir, note))
    return results


def ask(target_dir: Path, target: str, file: Path, timeout: float) -> str:
    """Run a target of the repository on one file: accepted, rejected, crash or hang."""
    import yaml  # fanbase needs it, so it is there

    folder = target_dir / target
    try:
        command = yaml.safe_load((folder / "target.yml").read_text())["run"]
    except (OSError, KeyError, TypeError, yaml.YAMLError):
        return "gone"  # the target is no longer there: nothing can be said
    fill = {"{python}": sys.executable, "{dir}": str(folder), "{file}": str(file)}
    argv = [fill.get(part, part) if part in fill else
            part.replace("{dir}", str(folder)).replace("{file}", str(file)).replace("{python}", sys.executable)
            for part in command]
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return "hang"
    except OSError:
        return "gone"
    return "accepted" if done.returncode == 0 else "crash" if done.returncode < 0 else "rejected"


def still_open(alerts: list[dict], target_dir: Path, shown_dir: str, timeout: float) -> tuple[list[dict], int]:
    """The open alerts whose input is still not accepted, as results; and how many are fixed."""
    kept, fixed = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for alert in alerts:
            text = (alert.get("most_recent_instance") or {}).get("message", {}).get("text", "")
            last = text.rstrip().rsplit("\n", 1)[-1]
            if not last.startswith(TRAILER):
                continue  # not one of ours, or cut short: it cannot be tried again
            try:
                again = json.loads(last[len(TRAILER):])
                data = base64.b64decode(again["input"])
            except (ValueError, KeyError):
                continue  # too large to have been kept
            extension = again["spec"].split("/")[0]
            file = Path(tmp) / f"input.{extension}"
            file.write_bytes(data)
            answers = {t: ask(target_dir, t, file, timeout) for t in again["targets"]}
            broke = again["kind"] not in LEVEL
            bad = [t for t, a in answers.items() if (a in ("crash", "hang") if broke else a != "accepted")]
            if not bad and "gone" not in answers.values():
                fixed += 1
                continue
            body = text.rstrip().rsplit("\n", 1)[0].rstrip()
            rule = alert["rule"]["id"]
            kept.append({"ruleId": rule, "level": LEVEL.get(again["kind"], "error"), "title": again["title"],
                         "message": {"text": body + "\n\n" + last},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": f"{shown_dir}/{again['targets'][0]}/target.yml"},
                             "region": {"startLine": 1}}}],
                         "partialFingerprints": {"fandangoFinding/v1": rule.split("/", 1)[-1]},
                         "carried": True})
    return kept, fixed


def sarif(results: list[dict]) -> dict:
    rules, seen = [], {}
    for r in results:  # one alert per kind of finding: the first of a kind stands for it
        if r["ruleId"] not in seen:
            seen[r["ruleId"]] = r
            rules.append({"id": r["ruleId"], "name": r["title"], "shortDescription": {"text": r["title"]},
                          "fullDescription": {"text": r["title"]},
                          "defaultConfiguration": {"level": r["level"]},
                          "helpUri": "https://github.com/fandango-fuzzer/fandango-action#reading-what-it-found"})
    clean = [{k: v for k, v in r.items() if k not in ("title", "carried")} for r in seen.values()]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "rules": rules,
                                          "informationUri": "https://github.com/fandango-fuzzer/fandango-action"}},
                      "results": clean}]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("record")
    parser.add_argument("target_dir")
    parser.add_argument("out")
    parser.add_argument("--open", help="the open alerts, as the code scanning API lists them (one a line)")
    parser.add_argument("--shown-dir", help="target_dir as a path of the repository (for the alert's place)")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    shown = args.shown_dir or args.target_dir
    new = from_record(Path(args.record), shown)
    carried, fixed = [], 0
    if args.open and Path(args.open).exists():
        alerts = []  # one alert a line, as `gh api --paginate --jq '.[]'` writes them
        for line in Path(args.open).read_text().splitlines():
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            alerts += [alert] if isinstance(alert, dict) else []
        carried, fixed = still_open(alerts, Path(args.target_dir), shown, args.timeout)
    document = sarif(new + carried)  # this run's word on a bug wins over the alert's older one
    Path(args.out).write_text(json.dumps(document, indent=1))
    total = len(document["runs"][0]["results"])
    again = total - len({r["ruleId"] for r in new})
    # Counts only: this goes to a log that everyone can read
    print(f"{total} alert(s): {total - again} from this run, {again} still open from before; "
          f"{fixed} fixed since the last run.")


if __name__ == "__main__":
    main()
