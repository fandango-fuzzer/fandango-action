# Fandango fuzz

A GitHub Action that fuzzes the program in your repository (a parser, a library, a command-line tool:
anything that reads files of some format) with inputs that [Fandango](https://github.com/fandango-fuzzer/fandango)
makes from [Fanbase](https://github.com/fandango-fuzzer/fanbase) specs, and puts what it finds where only
the people who maintain the repository can read it: its Security tab.

For each spec of your format, Fandango makes inputs, and your program is run on each one. Then:

- **If it crashes, hangs, or is killed for what it used,** that may be a vulnerability. The input and what the
  program printed are kept, away from the public log.
- **If it rejects an input that is valid** (the spec says its files always decode), that's a *finding*. Findings
  are grouped by what your program said, and one input of each group is reduced to a smaller one that it still
  rejects, so you get `1E0` rather than a 300-byte file.

Each kind of finding becomes a [code scanning alert](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/about-code-scanning-alerts)
of your repository, with the input and what your program said. People with write access to the repository read
them in its Security tab, and nobody else does. The log and the job summary show counts only. There is no key to
make and no secret to set.

## Getting started

**1. Say how to run your program on one file.** That is a *target*: a folder in `.fandango/targets/` with a
`target.yml` and, usually, a small harness. The harness exits 0 when your program accepts the file, and
something else when it doesn't:

```yaml
# .fandango/targets/myreader/target.yml
title: My JSON reader
formats: [json]                                  # the format it reads
run: ["{python}", "{dir}/harness.py", "{file}"]  # {file} is the input, {dir} this folder
```

```python
# .fandango/targets/myreader/harness.py
import sys
from myreader import load

load(sys.argv[1])  # an exception exits 1: it rejected the file
```

The harness can run your program however it is run: a Python import as above, or your binary, from a small
script next to it (`run: ["bash", "{dir}/harness.sh", "{file}"]`):

```bash
# .fandango/targets/myreader/harness.sh
here="$(dirname "$0")"
exec "$here/../../../build/myreader" --check "$1"   # the repository's own build
```

[example/](example/) is a whole project, with a reader that has two bugs in it on purpose; this repository's
own test fuzzes it.

**2. Add a workflow.**

```yaml
name: fuzz
on:
  schedule:
    - cron: "0 3 * * 1"   # every Monday
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # to report what is found as code scanning alerts

jobs:
  fuzz:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - run: make          # build your program, if it needs building
      - uses: fandango-fuzzer/fandango-action@v1
        with:
          specs: json json-boundary
```

Every target in `.fandango/targets/` that reads the specs' format is fuzzed. The specs are Fanbase's; see
[the formats it has](https://fandango-fuzzer.github.io/fanbase/).

**3. Read what it found.** Open the Security tab of your repository, and there Code scanning: each alert is one
kind of finding. Its title says which program and what it said (`myreader: ValueError: bad exponent …`), and the
alert holds the input, reduced, and the whole answer. You can dismiss one as you would any other alert (won't
fix, false positive), and it stays dismissed.

An alert is closed when its bug is fixed, and not before. The inputs of each run are random, so a bug may not
show up again the week after: that is why every run first tries the inputs of the alerts that are open, and an
alert stays open until your program accepts its input.

You can run the same on your machine: the record is then written in the clear, to a folder only you can read.

```bash
fanbase --registry path/to/fanbase fuzz json --target-dir .fandango/targets --record record
```

Start with `record/REPORT.md`. Each crash has a folder of its own, and each finding one under `findings/`, with
the reduced input, the original one, and what your program said.

## What stays private, and why

A crash can be a vulnerability that isn't fixed yet, and a public log is the wrong place for it. So:

- the log and the summary say how many inputs your program accepted, rejected, or failed on. A crash is counted
  as a failure, the same as a harness that fails, so the counts don't say that anything crashed;
- what was found goes to code scanning alerts. In a public repository too, only people with write access to it
  can list and read them;
- the action needs no secrets. It does need `security-events: write`, which the job's token doesn't have on a
  pull request from a fork: run it on a schedule, or on pushes, not on such pull requests;
- with `fail-on-findings: true`, a failed job says that something was found, and nothing more. In a public
  repository, you may prefer to leave it off and read the alerts.

Code scanning is free for public repositories. A private repository needs GitHub Code Security for it; without
it, use the encrypted record below.

## An encrypted record instead

If you can't use code scanning, or you'd rather not have what is found on GitHub at all, the action can keep it
in a file that only your key opens. Make an [age](https://age-encryption.org) key, and keep the private key to
yourself (and back it up: without it, nobody can read a record):

```bash
age-keygen -o fandango-key.txt
```

`age-keygen` prints the public key (`age1...`). That one isn't a secret: give it to the action.

```yaml
      - uses: fandango-fuzzer/fandango-action@v1
        with:
          specs: json json-boundary
          recipients: age1...your-public-key...
```

The record is encrypted before it leaves the runner and kept as the run's `fandango-record` artifact. Artifacts
of a public repository can be downloaded by anyone who is signed in to GitHub, which is fine for this one: only
your key opens it. It is written on every run, and its size is padded to whole megabytes, so having one says
nothing either. This way needs no permission beyond `contents: read`, so it runs on pull requests from forks
too. To read a record, download the artifact and open it with your key:

```bash
pip install fanbase
fanbase incidents open fuzz-private.age --identity fandango-key.txt --into record
```

## Only the program of your repository

The action fuzzes the program of the repository it runs in, and nothing else: its targets come only from
`target-dir`, a folder of that repository, and each of them runs a harness that is in it too. The Fanbase
registry's own targets (other people's parsers) are never taken, and a target that runs a program of the
machine directly, or a folder that links out of the repository, is refused.

A harness can still run anything, so this is a promise you make as much as a check: please use the action on
software you maintain, or that you are allowed to test. Bugs in other people's software are theirs to hear
about first, privately (see Fanbase's [ETHICS.md](https://github.com/fandango-fuzzer/fanbase/blob/main/ETHICS.md)).

## Several implementations in one repository

If your repository has more than one implementation of the format (a Python and a Java parser, say), give each
a target: all of them are fuzzed, and the inputs they disagree on are found too.

## Inputs

| input | default | what it is |
|---|---|---|
| `specs` | (required) | The Fanbase specs of your format, separated by spaces |
| `target-dir` | `.fandango/targets` | The folder that says how to run your program |
| `targets` | every target there that reads the format | Or name some of them, separated by commas |
| `report` | `alerts`, or `record` if you give `recipients` | Where what is found goes: code scanning alerts, or an encrypted record |
| `category` | `fandango` | The category of the code scanning analysis; give each job its own if several use the action |
| `recipients` | | For the record: the age public key(s), one per line |
| `recipients-file` | | Or a file of your repository that holds them |
| `count` | `200` | Inputs to make from each spec |
| `seed` | the run number | The random seed; the record says which one was used |
| `budget` | `300` | Seconds for Fandango to make the inputs of one spec |
| `timeout` | `10` | Seconds for your program to answer about one input |
| `reduce-budget` | `60` | Seconds to reduce the input of one finding |
| `fail-on-findings` | `false` | Fail the job when anything is found |
| `registry-repository`, `registry-ref` | `fandango-fuzzer/fanbase`, `main` | Where the specs come from |
| `fanbase`, `fandango` | `fanbase>=0.7`, `fandango-fuzzer` | The packages to install |
| `python-version` | `3.12` | The Python that runs everything |
| `setup-python` | `true` | `false` if you set up Python yourself first, for instance to install your program into it |
| `artifact-name`, `retention-days` | `fandango-record`, `30` | The artifact with the record |

Outputs: `findings` (how many kinds of finding there were), `sarif` (the alerts, as a SARIF file on the runner)
and `record` (the encrypted file on the runner, when the report is a record).

## What it doesn't do (yet)

- It runs on Linux and macOS runners, not on Windows.
- It doesn't build your program with sanitizers. A memory bug often doesn't crash without them, so if your
  program is in C or C++, building it with AddressSanitizer for this job finds more.
- The specs come from a Fanbase registry; a spec of your own has to be in one (your fork of it, for instance,
  with `registry-repository`).
- It doesn't open issues or send mail: what to report, and where, is your call.
- An alert keeps its input so that it can be tried again, up to 4 KB of it. An alert with a larger input is
  closed by the next run that doesn't find its bug again.

## License

Apache-2.0. See [LICENSE](LICENSE).
