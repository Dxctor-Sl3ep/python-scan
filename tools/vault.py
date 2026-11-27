from pathlib import Path
import subprocess
import warnings


VAULT_FILE = Path(__file__).resolve().parents[1] / ".env"
ANSIBLE_VAULT_HEADER = b"$ANSIBLE_VAULT;"


def read_vault_contents(path: Path = VAULT_FILE) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    try:
        contents = path.read_bytes()
    except OSError as error:
        raise RuntimeError(f"Could not read configuration file {path}: {error}") from error

    if not contents.startswith(ANSIBLE_VAULT_HEADER):
        warnings.warn(
            f"{path} is not encrypted with Ansible Vault. "
            "The file is ignored by Git, but its contents are not encrypted; "
            "run 'make vault-encrypt' to protect secrets at rest.",
            RuntimeWarning,
            stacklevel=2,
        )
        try:
            return contents.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError(
                f"Plain-text configuration file {path} is not valid UTF-8."
            ) from error

    try:
        result = subprocess.run(
            ["ansible-vault", "view", str(path)],
            capture_output=True,
            check=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            "'ansible-vault' was not found. Install the dependencies from requirement.txt."
        ) from error
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            "Could not decrypt the configuration. Check the vault password and file format."
        ) from error

    return result.stdout
