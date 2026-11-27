import hashlib
import re
from pathlib import Path

from tools.vault import read_vault_contents


SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


def parse_expected_hashes(vault_contents: str) -> dict[Path, str]:
    expected_hashes = {}
    for line_number, raw_line in enumerate(vault_contents.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("VIRUSTOTAL_API_KEY="):
            continue
        if ":" not in line:
            print(f"[WARNING] Ignoring invalid vault entry on line {line_number}.")
            continue

        file_path, expected_hash = line.rsplit(":", 1)
        file_path = file_path.strip().strip('"').strip("'")
        expected_hash = expected_hash.strip().lower()
        if not file_path or not SHA256_PATTERN.fullmatch(expected_hash):
            print(f"[WARNING] Ignoring invalid vault entry on line {line_number}.")
            continue
        expected_hashes[Path(file_path).expanduser()] = expected_hash
    return expected_hashes


def calculate_sha256(path: Path) -> str:
    sha256 = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_integrity() -> int:
    print("Opening the configuration...")
    try:
        expected_hashes = parse_expected_hashes(read_vault_contents())
    except (FileNotFoundError, RuntimeError) as error:
        print(f"[ERROR] {error}")
        return 1

    if not expected_hashes:
        print(
            "[INFO] No valid file hashes found in the vault "
            "(expected format: path : SHA-256)."
        )
        return 0

    print("\n=== FILE INTEGRITY CHECK ===\n")
    has_errors = False
    for file_path, expected_hash in expected_hashes.items():
        if not file_path.is_file():
            print(f"[ALERT] FILE MISSING: {file_path}")
            has_errors = True
            continue

        try:
            current_hash = calculate_sha256(file_path)
            if current_hash == expected_hash:
                print(f"[OK] {file_path}")
            else:
                print(f"[CRITICAL ALERT] MODIFICATION DETECTED: {file_path}")
                print(f"   Expected: {expected_hash}")
                print(f"   Current:  {current_hash}")
                has_errors = True
        except OSError as error:
            print(f"[ERROR] Cannot read {file_path}: {error}")
            has_errors = True
    return int(has_errors)


if __name__ == "__main__":
    raise SystemExit(verify_integrity())