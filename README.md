# Fandango fuzz

Fuzz the program in your repository with valid inputs of its format, and read what breaks in the Security tab.

[Fandango](https://github.com/fandango-fuzzer/fandango) makes the inputs from
[Fanbase](https://github.com/fandango-fuzzer/fanbase) specs: JSON, XML, PNG, ZIP, WAV and
[about forty formats in all](https://fandango-fuzzer.github.io/fanbase/). Every input is valid, so when your
program rejects one, or crashes on it, that is a bug to look at.

## Set it up

Add one file, `.github/workflows/fuzz.yml`:

```yaml
name: fuzz
on:
  schedule:
    - cron: "0 3 * * 1"   # every Monday
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  fuzz:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - run: make                                # build your program, if it needs building
      - uses: fandango-fuzzer/fandango-action@v1
        with:
          specs: json                            # the format your program reads
          run: ./build/myreader --check {file}   # how to run it on one file
```

`run` is any command; `{file}` is the input. Exit status 0 means your program accepted the file, anything else
that it didn't. That's all: no key, no secret, no account.

## Read what it found

Open **Security → Code scanning** in your repository. Each alert is one bug:

- its title is the program and the error (`myreader: ValueError: bad exponent`);
- it holds the input, reduced to a small one, and what your program said;
- it ends with two lines to paste in a terminal that write the input to a file and run your program on it.

An alert closes by itself once your program accepts its input. Dismiss one (won't fix, false positive) and it
stays dismissed.

Only people with write access to the repository can read these alerts. The job's log shows counts only.

The page shows your default branch at first. If the job ran on another branch, follow the link in the run's
summary, or change the filter to `branch:NAME`.

## Good to know

- **Runs on a schedule or on pushes**, not on pull requests from forks: those can't write alerts.
- **Private repositories** need GitHub Code Security for code scanning. Without it, use the
  [encrypted record](#an-encrypted-record-instead).
- **An error that over 20% of the inputs get** is reported as a note, not a warning: your program probably
  doesn't support that part of the format, and you can dismiss it.
- **At most 10 new alerts per run.** Crashes come first; the rest wait for the next run.
- **C or C++?** Build with AddressSanitizer for this job: memory bugs often don't crash without it.
- Linux and macOS runners only.

## More than one command: targets

If running your program takes more than a command (a Python import, several implementations of the format),
leave `run` out and add a folder for each program:

```yaml
# .fandango/targets/myreader/target.yml
title: My JSON reader
formats: [json]
run: ["{python}", "{dir}/harness.py", "{file}"]
```

```python
# .fandango/targets/myreader/harness.py
import sys
from myreader import load

load(sys.argv[1])  # an exception exits 1: the file is rejected
```

Every target that reads the spec's format is fuzzed, and where two of them disagree on an input is reported
too. [example/](example/) is a small project set up this way.

Have the harness print one line that says what is wrong (`ValueError: bad exponent`): alerts are grouped by it.

## An encrypted record instead

To keep what is found off GitHub, give the action an [age](https://age-encryption.org) public key. The findings
then go to a file that only your private key opens, kept as an artifact of the run, and no alerts are written.

```bash
age-keygen -o fandango-key.txt   # prints the public key; keep the file to yourself
```

```yaml
      - uses: fandango-fuzzer/fandango-action@v1
        with:
          specs: json
          run: ./build/myreader --check {file}
          recipients: age1...your-public-key...
```

```bash
pip install fanbase
fanbase incidents open fuzz-private.age --identity fandango-key.txt --into record
```

This way needs only `contents: read`, so it also runs on pull requests from forks.

## Inputs

| input | default | what it is |
|---|---|---|
| `specs` | (required) | The Fanbase specs of your format, separated by spaces |
| `run` | | How to run your program on one file, with `{file}` for the input |
| `name` | the repository's name | With `run`, what to call your program in the alerts |
| `target-dir` | `.fandango/targets` | Without `run`: the folder with your targets |
| `targets` | all that read the format | Or name some of them, separated by commas |
| `count` | `200` | Inputs to make from each spec |
| `seed` | the run number | The random seed, so every run tries new inputs |
| `timeout` | `10` | Seconds for your program to answer about one input |
| `budget` | `300` | Seconds for Fandango to make the inputs of one spec |
| `reduce-budget` | `60` | Seconds to reduce the input of one finding |
| `note-above` | `20` | Percent of the inputs above which an error is a note |
| `max-new-alerts` | `10` | The most alerts one run opens |
| `fail-on-findings` | `false` | Fail the job when anything is found |
| `category` | `fandango` | Code scanning category; give each job its own if several use the action |
| `report` | `alerts`, or `record` with `recipients` | Where findings go |
| `recipients`, `recipients-file` | | The age public key(s), for the encrypted record |
| `artifact-name`, `retention-days` | `fandango-record`, `30` | The artifact with the encrypted record |
| `registry-repository`, `registry-ref` | `fandango-fuzzer/fanbase`, `main` | Where the specs come from |
| `fanbase`, `fandango` | `fanbase>=0.7`, `fandango-fuzzer` | The packages to install |
| `python-version`, `setup-python` | `3.12`, `true` | `setup-python: false` if you set up Python yourself first |
| `token` | the job's token | Lists the open alerts, so that they are tried again |

Outputs: `findings` (how many kinds of finding), `sarif` (the alerts file) and `record` (the encrypted file).

## Use it on your own software

The action only fuzzes the program of the repository it runs in. Please use it on software you maintain or are
allowed to test: bugs in other people's software are theirs to hear about first, privately (see Fanbase's
[ETHICS.md](https://github.com/fandango-fuzzer/fanbase/blob/main/ETHICS.md)).

## License

Apache-2.0. See [LICENSE](LICENSE).
