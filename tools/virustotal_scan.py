import argparse
import hashlib
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request

from tools.vault import read_vault_contents


VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files"
DEFAULT_SCAN_PATH = Path.home() / "Downloads"
REQUEST_TIMEOUT_SECONDS = 20
REQUEST_DELAY_SECONDS = 15
MAX_REQUESTS_PER_RUN = 20


def get_api_key() -> str:
    vault_contents = read_vault_contents()
    for line in vault_contents.splitlines():
        name, separator, value = line.strip().partition("=")
        if separator and name.strip() == "VIRUSTOTAL_API_KEY":
            api_key = value.strip().strip("\"'")
            if api_key:
                return api_key
            raise ValueError("VIRUSTOTAL_API_KEY is empty in .env.")

    raise ValueError("VIRUSTOTAL_API_KEY is missing from .env.")


def iter_files(paths: list[str], errors: list[str]) -> Iterator[Path]:
    for raw_path in paths:
        root = Path(raw_path).expanduser()
        if not root.exists():
            raise ValueError(f"Scan path does not exist: {root}")
        if root.is_symlink():
            raise ValueError(f"Refusing to scan a symbolic-link root: {root}")
        if root.is_file():
            yield root
            continue
        if not root.is_dir():
            raise ValueError(f"Scan path is not a regular file or directory: {root}")

        def report_walk_error(error: OSError) -> None:
            message = f"Cannot access directory {error.filename}: {error.strerror}"
            print(f"[ERROR] {message}")
            errors.append(message)

        for current_directory, directory_names, file_names in os.walk(
            root, followlinks=False, onerror=report_walk_error
        ):
            current_path = Path(current_directory)
            directory_names[:] = [
                name
                for name in directory_names
                if not (current_path / name).is_symlink()
            ]
            for name in file_names:
                file_path = current_path / name
                if not file_path.is_symlink() and file_path.is_file():
                    yield file_path


def calculate_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lookup_hash(sha256: str, api_key: str) -> dict[str, int] | None:
    request = urllib.request.Request(
        f"{VIRUSTOTAL_FILE_URL}/{sha256}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            payload: Any = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        if error.code == 429:
            raise RuntimeError(
                "VirusTotal rate limit reached. The scan stopped; try again later."
            ) from error
        if error.code == 405:
            raise RuntimeError(
                "VirusTotal rejected the HTTP method. File reports require "
                "GET /api/v3/files/{sha256}."
            ) from error
        raise RuntimeError(
            f"VirusTotal returned HTTP {error.code} while looking up a hash."
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(
            f"Could not connect to VirusTotal: {error.reason}"
        ) from error
    except (TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Could not read the VirusTotal response: {error}") from error

    try:
        attributes = payload["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
    except (KeyError, TypeError) as error:
        raise RuntimeError("VirusTotal returned an unexpected file report.") from error

    if not isinstance(stats, dict):
        return {}
    return {
        name: int(stats.get(name, 0) or 0)
        for name in ("malicious", "suspicious", "harmless", "undetected")
    }


def describe_report(report: dict[str, int] | None) -> str:
    if report is None:
        return "NOT FOUND - no exact-hash report; reputation is unknown"
    if not report:
        return "REPORT FOUND - no analysis statistics available"

    stats = ", ".join(
        f"{name}={report[name]}"
        for name in ("malicious", "suspicious", "harmless", "undetected")
    )
    if report["malicious"] or report["suspicious"]:
        return f"FLAGGED - {stats}"
    return f"NO FLAGGED DETECTIONS - {stats}"


def main(paths: list[str] | None = None) -> int:
    scan_paths = paths or [str(DEFAULT_SCAN_PATH)]
    try:
        api_key = get_api_key()
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        print(f"[ERROR] {error}")
        return 1

    scan_errors: list[str] = []
    checked_hashes: dict[str, dict[str, int] | None] = {}
    scanned_files = 0
    request_limit_reached = False

    try:
        for file_path in iter_files(scan_paths, scan_errors):
            try:
                sha256 = calculate_sha256(file_path)
            except OSError as error:
                message = f"Cannot read {file_path}: {error}"
                print(f"[ERROR] {message}")
                scan_errors.append(message)
                continue

            if sha256 not in checked_hashes:
                if len(checked_hashes) >= MAX_REQUESTS_PER_RUN:
                    print(
                        "[WARNING] Per-run VirusTotal request limit "
                        f"({MAX_REQUESTS_PER_RUN}) reached; stopping the scan."
                    )
                    request_limit_reached = True
                    break
                try:
                    checked_hashes[sha256] = lookup_hash(sha256, api_key)
                    time.sleep(REQUEST_DELAY_SECONDS)
                except RuntimeError as error:
                    print(f"[ERROR] {error}")
                    return 1

            scanned_files += 1
            print(f"{file_path}: {describe_report(checked_hashes[sha256])}")
    except (OSError, ValueError) as error:
        print(f"[ERROR] {error}")
        return 1

    print(
        f"\nScanned {scanned_files} file(s); "
        f"looked up {len(checked_hashes)} unique SHA-256 hash(es)."
    )
    if request_limit_reached:
        print("[WARNING] Scan incomplete because the per-run request limit was reached.")
        return 1
    if scan_errors:
        print(f"[WARNING] {len(scan_errors)} file or directory access error(s).")
        return 1
    if scanned_files == 0:
        print("[INFO] No files were found in the selected path(s).")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Recursively hash local files and check exact SHA-256 matches "
            "with VirusTotal. File contents are never uploaded."
        )
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help=f"File or directory paths to scan (default: {DEFAULT_SCAN_PATH})",
    )
    raise SystemExit(main(parser.parse_args().paths))
