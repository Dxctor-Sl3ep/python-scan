# Python Scan

## Project goal

Python Scan is a small collection of command-line utilities for basic
defensive checks:

- compare files with known SHA-256 hashes to detect changes;
- inspect SSH authentication logs for repeated failed logins;
- check local file hashes against VirusTotal reports.

## Status: proof of concept

This project is **only a proof of concept (POC)**. It is not antivirus software,
does not continuously monitor or protect a computer, and does not remove or
quarantine files. VirusTotal results depend on its available reports, and an
unknown hash or a report with no detections is not proof that a file is safe.
Use it for learning and controlled testing, not as the sole security control.

The tools are separate command-line scripts; there is no server to start.

## Requirements

- Python 3
- GNU Make
- `ansible-core`, which provides the `ansible-vault` command
- A VirusTotal API key for VirusTotal hash lookups

## Initialize the project

Run these commands from the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
make install
make help
```

`make install` installs `ansible-core`. The Python tools otherwise use the
standard library.

### Configure Ansible Vault

Create a `.env` file in the repository root with your VirusTotal API key and,
optionally, the files you want the integrity checker to monitor:

```text
VIRUSTOTAL_API_KEY=<your-api-key>
/absolute/path/to/file : <64-character-SHA-256>
```

Use an editor to enter the API key; do not put a real key in source control.
The `.env` file is ignored by Git. The tools can read either a plain-text
`.env` or an Ansible Vault-encrypted `.env`; a warning is shown when the file
is plain text. `.gitignore` prevents accidental Git tracking but does not
encrypt the file, so encrypt it to protect secrets at rest.

To calculate a file's expected hash on Linux, run:

```sh
sha256sum /absolute/path/to/file
```

Copy the 64-character hash into the configuration entry. To encrypt the initial
configuration, run:

```sh
make vault-encrypt
```

Edit a plain-text `.env` with a text editor. After encrypting it, use
`make vault-edit` for later changes. Encrypted configuration is read through
`ansible-vault view` and kept in memory.

## Run the tools

```sh
make integrity-check
make virustotal-scan
python -m tools.log_analyze
```

The VirusTotal scan recursively checks `~/Downloads` by default. To choose a
different file or directory:

```sh
make virustotal-scan SCAN_PATH=/path/to/scan
```

It calculates SHA-256 locally and sends only the hashes to VirusTotal; it does
not upload file contents. Lookups are for exact hashes, not similar files.
The scanner waits 15 seconds after each unique-hash lookup, spacing requests
for a four-requests-per-minute limit and makes at most 20 VirusTotal requests
per run. If it encounters another unique hash, it stops and reports an
incomplete scan. This per-run cap does not prevent exhausting a
100-requests-per-day quota across multiple runs.

The SSH analyzer reads `/var/log/auth.log` by default. On systems that use
`/var/log/secure`, update `AUTH_LOG_FILE` in `tools/log_analyze.py` before
running it. Reading system authentication logs may require elevated
permissions.

## Test the POC

There is currently **no automated test suite** or `make test` target. These
smoke checks can be run from the repository root.

Check Python syntax and available Make targets:

```sh
python -m compileall -q tools
make help
```

Test the SSH analyzer with a temporary synthetic log, without reading system
logs or needing elevated permissions:

```sh
python - <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.log_analyze import analyze_ssh_logs

failed_login = (
    "sshd[123]: Failed password for invalid user demo "
    "from 203.0.113.10 port 22 ssh2\n"
)

with TemporaryDirectory() as directory:
    log_path = Path(directory) / "auth.log"
    log_path.write_text(failed_login * 5, encoding="utf-8")
    analyze_ssh_logs(log_path)
PY
```

For an integrity-check smoke test, create a harmless temporary file, calculate
its SHA-256, add a `path : hash` entry with `make vault-edit`, then run
`make integrity-check`. It should report `[OK]`; changing the file should
produce a modification alert.

To try the VirusTotal scan, scan a harmless test file with
`make virustotal-scan SCAN_PATH=/path/to/test-file`. This requires a configured
API key and an internet connection. Only the test file's hash is sent. A
missing report is an unknown result, not a clean bill of health.

See [`tools/README.md`](tools/README.md) for what each utility does and for
tool-specific notes.
