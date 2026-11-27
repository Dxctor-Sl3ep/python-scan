# Tools

These utilities are intended for learning and controlled POC testing. Run
commands from the repository root so Python can import the `tools` package.

## `integrity_check.py`

Checks whether files still match their expected SHA-256 hashes. It reads
`../.env` as plain text or through Ansible Vault and accepts one entry per line
in this format:

```text
/path/to/file : <64-character-SHA-256>
```

Run it with `make integrity-check`. Missing files, unreadable files, or
modified contents are reported as alerts. The `VIRUSTOTAL_API_KEY` entry is
ignored by this checker.

## `log_analyze.py`

Reads an SSH authentication log and counts failed password attempts by source
IP address and targeted username. It reports a critical alert for an IP with
five or more failures. The default input is `/var/log/auth.log`; on systems
using `/var/log/secure`, change `AUTH_LOG_FILE` in the script.

Run it with `python -m tools.log_analyze`. Reading the system log may require
elevated permissions. `sample.log` contains generic web-server entries, not
`sshd` authentication entries, so it is not a positive test fixture for this
analyzer.

## `virustotal_scan.py`

Recursively scans the supplied file or directory, calculates each file's
SHA-256 locally, and requests a VirusTotal report for each unique hash. If no
path is supplied, it scans `~/Downloads`. Run it with
`make virustotal-scan`, or pass a different path using
`make virustotal-scan SCAN_PATH=/path/to/scan`.

The API key is read from the `VIRUSTOTAL_API_KEY` entry in `../.env`, whether
the file is plain text or encrypted with Ansible Vault. Plain-text mode emits
a warning because Git ignore rules do not encrypt secrets. Only hashes are
sent; file contents are never uploaded. The lookup is for an exact hash, not a
similar hash. A missing VirusTotal report means the file's reputation is
unknown. The scanner waits 15 seconds after each unique-hash lookup and makes
at most 20 VirusTotal requests per run. It stops with an incomplete-scan
warning if it encounters another unique hash. This cap does not prevent a
100-per-day quota from being exhausted across multiple runs. A rate-limit
response also stops the scan.

## `vault.py`

Shared helper used by the other tools to read the repository's `.env` file.
Plain-text files are read with a warning; Ansible Vault files are read with
`ansible-vault view`. Decrypted output is returned to the caller in memory and
is not written to a plaintext configuration file.

## Package and sample files

- `__init__.py` makes `tools` importable as a Python package.
- `sample.log` is generic web-server sample data; the current SSH analyzer
  does not parse its entries.
- `baseline.json` is currently an empty placeholder and is not read by these
  tools.
