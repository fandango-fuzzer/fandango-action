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
import shlex
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


PLAIN = frozenset("a an and are as at be but by for from has in is it no not of on or that the to was with".split())
WORD = re.compile(r"[^\s\"'`()\[\]{},;:=<>]+")


def normalise(why: str, data: bytes | None = None) -> str:
    """What a program said, without what changes from one input to the next: the class of the error.
    A word of the message that is a word of the input (a name, a number, a token of it) is left out:
    that is the part that is about this input."""
    if data:
        text = data.decode("utf-8", errors="replace")
        quoted = {q for pair in re.findall(r'"([^"\n]+)"|\'([^\'\n]+)\'', text) for q in pair if q}
        for phrase in sorted(quoted - PLAIN, key=len, reverse=True):
            # a quoted name of the input, said without quotes: the whole of it, not a part of another word
            why = re.sub(rf"(?<![\w.]){re.escape(phrase)}(?![\w])", "…", why)
        mine = set(WORD.findall(text)) - PLAIN
        # and the parts of a word that punctuation joins (a.b, !name, f(x)): a program names one of them
        mine |= {part for word in mine for part in re.split(r"[^\w]+", word) if len(part) > 1} - PLAIN
        why = WORD.sub(lambda m: "…" if m.group().rstrip(".") in mine else m.group(), why)
    why = re.sub(r"\{.*|\\n.*", "", why.replace('b"', ""))  # a dump of names, a second line
    why = re.sub(r'"[^"]*"|\'[^\']*\'|`[^`]*`', "…", why)
    # names and numbers of this input, but not the name of an error (Z3Exception)
    why = re.sub(r"\b(?!\w*(?:Error|Exception)\b)\w*\d\w*\b", "…", why)
    why = re.sub(r"(input|at|near|got|found|line|column|offset)\b:? .*", r"\1 …", why, flags=re.I)
    why = re.sub(r"^(?:[A-Z]+:[\w.]+:\s*)+", "", why.strip())  # a logger's "ERROR:its.name:" in front
    words = ["…" if "…" in word else word for word in why.split()]
    for i, word in enumerate(words):  # a scrap next to a name left out was part of the name
        scrap = len(word) <= 2 and word.lower() not in PLAIN and not word.endswith(":")
        if scrap and "…" in words[max(0, i - 1):i + 2]:
            words[i] = "…"
    why = re.sub(r"(…\s*)+", "… ", " ".join(words)).strip()
    why = re.sub(r":?\s*…$", "", why) if why.count(": ") >= 2 or why.endswith(":…") else why
    cut = why.find("…", 20)  # what follows the first name left out is mostly more of the input
    why = why[:cut + 1] if cut >= 0 else why
    why = ": ".join(why.split(": ")[:2])  # "Error: what is wrong: with what" stops before the last part
    return why[:90].rstrip(" :,;") or "rejected"


def show(data: bytes) -> str:
    cut = data[:SHOWN]
    try:
        text = cut.decode("utf-8")
        if any(ord(c) < ord(" ") and c not in "\n\t\r" for c in text):
            raise ValueError
    except ValueError:
        text = cut.hex(" ", 1)
    return text + (f"\n... ({len(data) - SHOWN} more bytes)" if len(data) > SHOWN else "")


def command(target: str, name: str, place: str, target_dir: Path | None, run: str) -> str:
    """What to type, at the root of the repository, to run a target on the file `name`."""
    if run:  # the workflow's own command
        return run.replace("{file}", name) if "{file}" in run else f"{run} {name}"
    if target_dir is None or "{target}" not in place:
        return ""
    try:
        import yaml  # fanbase needs it, so it is there

        parts = yaml.safe_load((target_dir / target / "target.yml").read_text())["run"]
    except (OSError, KeyError, TypeError, ImportError, ValueError):
        return ""
    folder = place.replace("{target}", target).rsplit("/", 1)[0]
    fill = {"{python}": "python", "{dir}": folder, "{file}": name}
    done = []
    for part in parts:
        for key, value in fill.items():
            part = str(part).replace(key, value)
        done.append(shlex.quote(part))
    return " ".join(done)


def reproduce(targets: list[str], spec: str, data: bytes | None, place: str, target_dir: Path | None,
              run: str) -> list[str]:
    """The lines of an alert that say how to see the bug again: write the input, run the program on it."""
    if data is None or len(data) > KEPT:
        return []
    name = f"input.{spec.split('/')[0]}"
    commands = [c for c in (command(t, name, place, target_dir, run) for t in targets) if c]
    if not commands:
        return []
    return ["", "To reproduce, at the root of the repository:", "",
            f"echo {base64.b64encode(data).decode()} | base64 -d > {name}", *dict.fromkeys(commands)]


def result(kind: str, spec: str, said: list[tuple[str, str]], others: list[tuple[str, str]],
           accepted: list[str], data: bytes | None, place: str, note: str = "", seen: int = 1,
           target_dir: Path | None = None, run: str = "") -> dict:
    """One alert: the programs that said the same of an input, and what they said. `others` did not
    accept the input either, but said something else."""
    targets = sorted(t for t, _ in said)
    why = said[0][1]
    names = ", ".join(targets) if len(targets) <= 3 else f"{len(targets)} programs"  # noqa: PLR2004
    title = f"{names}: {normalise(why, data) if kind in LEVEL else BROKE.get(kind, kind)}"
    print_ = hashlib.sha256(f"{kind}|{','.join(targets)}|{title}".encode()).hexdigest()[:16]
    one = len(targets) == 1
    if kind in LEVEL:
        head = f"{', '.join(targets)} reject{'s' if one else ''} a valid {spec} input"
        head += f" that {', '.join(accepted)} accept{'s' if len(accepted) == 1 else ''}." if accepted else "."
    else:
        head = f"{targets[0]} {BROKE.get(kind, kind)} on a {spec} input."
    lines = [head, "", *[f"{t}: {w}" for t, w in sorted(said)]]
    if others:
        lines += ["", "Of the same input:", *[f"{t}: {w}" for t, w in others]]
    again = {"v": 1, "kind": kind, "spec": spec, "targets": targets, "title": title}
    if data is not None:
        lines += ["", f"The input ({len(data)} bytes){note}:", "", show(data)]
        if len(data) <= KEPT:
            again["input"] = base64.b64encode(data).decode()
    lines += reproduce(targets, spec, data, place, target_dir, run)
    lines += ["", TRAILER + json.dumps(again, separators=(",", ":"))]
    return {"ruleId": f"{kind}/{print_}", "level": LEVEL.get(kind, "error"), "title": title,
            "message": {"text": "\n".join(lines)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": place.replace("{target}", targets[0])},
                "region": {"startLine": 1}}}],
            "partialFingerprints": {"fandangoFinding/v1": print_}, "seen": {spec: seen}}


def from_record(record: Path, place: str, target_dir: Path | None = None,
                timeout: float = 10, run: str = "") -> tuple[list[dict], int]:
    """The alerts of this run's record (the folder `fanbase fuzz --record` wrote), one for each program and
    class of what it said; and how many inputs each spec made."""
    if not (record / "manifest.json").exists():  # fanbase writes it into a folder of its own
        inside = sorted(record.glob("*/manifest.json"))
        if not inside:
            return [], 0  # nothing was found, so no record was written
        record = inside[0].parent
    manifest = json.loads((record / "manifest.json").read_text())
    results = []
    for finding in manifest.get("findings", []):
        said = [(t, why) for t, answer, why in finding["answers"] if answer != "accepted"]
        accepted = [t for t, answer, _ in finding["answers"] if answer == "accepted"]
        reduced = sorted((record / "findings" / finding["id"]).glob("reduced.*"))
        data = reduced[0].read_bytes() if reduced else None
        if reduced and target_dir is not None:
            # The record keeps the start of what a program said. The class of an error needs all of it, so
            # the program is asked once more about the reduced input.
            whole = {t: ask_in_full(target_dir, t, reduced[0], timeout, " ".join(why.split())) for t, why in said}
            said = [(t, whole[t][1] if whole[t][0] == "rejected" and whole[t][1] else why) for t, why in said]
        note = f", reduced, as {finding.get('inputs', 1)} input(s) of this run"
        kind = "disagreement" if accepted else "rejected"
        same: dict[str, list[tuple[str, str]]] = {}
        for one in said:  # the programs that said the same are one alert: one bug, where they all pass
            same.setdefault(normalise(one[1], data), []).append(one)
        for group in same.values():
            others = [other for other in said if other not in group]
            results.append(result(kind, finding["spec"], group, others, accepted, data, place, note,
                                  seen=finding.get("inputs", 1), target_dir=target_dir, run=run))
    for incident in manifest.get("incidents", []):
        inputs = [record / i["file"] for i in incident.get("inputs", []) if (record / i["file"]).exists()]
        data = min((p.read_bytes() for p in inputs), key=len, default=None)
        stderr = record / incident["id"] / "stderr.txt"
        said = stderr.read_text(errors="replace").strip()[-600:] if stderr.exists() else ""
        how = incident.get("signal") or f"exit status {incident.get('returncode')}"
        note = f", the smallest of {incident.get('occurrences', 1)}"
        results.append(result(incident["kind"], incident["spec"], [(incident["target"], f"{how}. {said}")],
                              [], [], data, place, note, seen=incident.get("occurrences", 1),
                              target_dir=target_dir, run=run))
    merged: dict[str, dict] = {}
    for r in results:  # the first of a class stands for it, and counts the inputs of them all
        if r["ruleId"] in merged:
            seen = merged[r["ruleId"]]["seen"]
            for spec, n in r["seen"].items():
                seen[spec] = seen.get(spec, 0) + n
        else:
            merged[r["ruleId"]] = r
    return list(merged.values()), int(manifest.get("count") or 0)


def calibrate(results: list[dict], count: int, note_above: float) -> None:
    """A class of rejection that a large share of a spec's inputs get is more likely a kind of input the
    program is not meant to read (or a harness that asks for more than the spec promises) than a bug:
    it becomes a note, and says so."""
    for r in results:
        share = max(r["seen"].values()) / count if count else 0
        r["share"] = share
        if r["level"] == "warning" and share * 100 > note_above:
            r["level"] = "note"
            head, rest = r["message"]["text"].split("\n", 1)
            r["message"]["text"] = (
                f"{head} {round(share * 100)}% of the inputs of a spec get this answer. That many is more often "
                "a kind of input the program is not meant to read, or a harness that asks for more than the spec "
                "promises, than a bug: dismiss the alert if so.\n" + rest)
        # the level goes with the alert, so that it is the same when the alert is tried again
        text, last = r["message"]["text"].rsplit("\n", 1)
        again = json.loads(last[len(TRAILER):]) | {"level": r["level"]}
        r["message"]["text"] = text + "\n" + TRAILER + json.dumps(again, separators=(",", ":"))


def newest(results: list[dict], open_rules: set[str], most: int) -> tuple[list[dict], int]:
    """At most `most` alerts that are not open yet: what broke the program first, then the rarer answers
    (a rare one is more likely a bug), the notes last. The rest wait for another run."""
    known = [r for r in results if r["ruleId"] in open_rules]
    new = [r for r in results if r["ruleId"] not in open_rules]
    order = {"error": 0, "warning": 1, "note": 2}
    new.sort(key=lambda r: (order.get(r["level"], 1), r.get("share", 0)))
    return known + new[:most], max(0, len(new) - most)


def ask(target_dir: Path, target: str, file: Path, timeout: float) -> str:
    """Run a target of the repository on one file: accepted, rejected, crash or hang."""
    return ask_in_full(target_dir, target, file, timeout)[0]


def ask_in_full(target_dir: Path, target: str, file: Path, timeout: float, start: str = "") -> tuple[str, str]:
    """The same, with the line of what the program said that begins as `start` does (else the last one)."""
    import yaml  # fanbase needs it, so it is there

    folder = target_dir / target
    try:
        command = yaml.safe_load((folder / "target.yml").read_text())["run"]
    except (OSError, KeyError, TypeError, yaml.YAMLError):
        return "gone", ""  # the target is no longer there: nothing can be said
    fill = {"{python}": sys.executable, "{dir}": str(folder), "{file}": str(file)}
    argv = [fill.get(part, part) if part in fill else
            part.replace("{dir}", str(folder)).replace("{file}", str(file)).replace("{python}", sys.executable)
            for part in command]
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return "hang", ""
    except OSError:
        return "gone", ""
    lines = [" ".join(line.split()) for line in (done.stderr or done.stdout).decode("utf-8", errors="replace").splitlines()]
    lines = [line for line in lines if line]
    begins = [line for line in lines if start and start[:40] in line]
    said = (begins or lines or [""])[-1 if not begins else 0][:1000]
    return ("accepted" if done.returncode == 0 else "crash" if done.returncode < 0 else "rejected"), said


def still_open(alerts: list[dict], target_dir: Path, place: str, timeout: float) -> tuple[list[dict], int]:
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
            level = again.get("level") or LEVEL.get(again["kind"], "error")
            kept.append({"ruleId": rule, "level": level, "title": again["title"],
                         "message": {"text": body + "\n\n" + last},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": place.replace("{target}", again["targets"][0])},
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
    extra = ("title", "carried", "seen", "share")
    clean = [{k: v for k, v in r.items() if k not in extra} for r in seen.values()]
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
    parser.add_argument("--place", help="the file of the repository an alert points at; {target} is the "
                        "target's name (default: TARGET_DIR/{target}/target.yml)")
    parser.add_argument("--run", default="", help="the workflow's command, when there is no target folder: "
                        "it is what an alert says to run")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--note-above", type=float, default=20, metavar="PERCENT",
                        help="a class of rejection that more than this share of a spec's inputs get is a note")
    parser.add_argument("--max-new", type=int, default=10, help="new alerts a run may open")
    args = parser.parse_args()
    place = args.place or f"{args.target_dir}/{{target}}/target.yml"
    new, count = from_record(Path(args.record), place, Path(args.target_dir), args.timeout, args.run)
    calibrate(new, count, args.note_above)
    carried, fixed = [], 0
    if args.open and Path(args.open).exists():
        alerts = []  # one alert a line, as `gh api --paginate --jq '.[]'` writes them
        for line in Path(args.open).read_text().splitlines():
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            alerts += [alert] if isinstance(alert, dict) else []
        carried, fixed = still_open(alerts, Path(args.target_dir), place, args.timeout)
    new, waiting = newest(new, {r["ruleId"] for r in carried}, args.max_new)
    document = sarif(new + carried)  # this run's word on a bug wins over the alert's older one
    Path(args.out).write_text(json.dumps(document, indent=1))
    total = len(document["runs"][0]["results"])
    again = total - len(new)
    notes = sum(r["level"] == "note" for r in new)
    # Counts only: this goes to a log that everyone can read
    print(f"{total} alert(s): {len(new)} from this run, {again} still open from before; "
          f"{fixed} fixed since the last run."
          + (f" {notes} of this run's are notes: an answer that so many inputs get is rarely a bug." if notes else "")
          + (f" {waiting} more kind(s) wait for another run (a run opens at most {args.max_new})." if waiting else ""))


if __name__ == "__main__":
    main()
