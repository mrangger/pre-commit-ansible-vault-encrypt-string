from __future__ import annotations

import argparse
import configparser
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap


class HookError(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt all top-level values in *_vault.yaml files with "
            "ansible-vault encrypt_string and export *_vault.plain.yaml mirrors."
        )
    )
    parser.add_argument("files", nargs="*", help="Files passed by pre-commit")
    parser.add_argument("--vault-password-file", help="Override Ansible vault password file")
    parser.add_argument("--ansible-cfg", help="Path to ansible.cfg used for password lookup")
    parser.add_argument(
        "--encrypt-vault-id",
        default="default",
        help="Vault ID to use for ansible-vault encrypt_string",
    )
    parser.add_argument("--file-suffix", default="_vault.yaml", help="Vault file suffix to process")
    parser.add_argument(
        "--plain-suffix",
        default=".plain",
        help="Text inserted before the YAML extension for plaintext exports",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    files = [Path(name) for name in args.files if name.endswith(args.file_suffix)]
    if not files:
        return 0

    try:
        password_file = resolve_vault_password_file(args, Path.cwd())
        modified = process_files(
            files=files,
            vault_password_file=password_file,
            encrypt_vault_id=args.encrypt_vault_id,
            plain_suffix=args.plain_suffix,
        )
    except HookError as exc:
        print(f"ansible-vault-encrypt-string: {exc}", file=sys.stderr)
        return 1

    if modified:
        for path in modified:
            print(f"ansible-vault-encrypt-string: updated {path}", file=sys.stderr)
        print("ansible-vault-encrypt-string: stage updated vault file(s) and re-run commit", file=sys.stderr)
        return 1

    return 0


def process_files(
    files: Iterable[Path],
    vault_password_file: Path,
    encrypt_vault_id: str,
    plain_suffix: str,
) -> list[Path]:
    modified: list[Path] = []
    for path in files:
        changed = process_file(
            path=path,
            vault_password_file=vault_password_file,
            encrypt_vault_id=encrypt_vault_id,
            plain_suffix=plain_suffix,
        )
        if changed:
            modified.append(path)
    return modified


def process_file(path: Path, vault_password_file: Path, encrypt_vault_id: str, plain_suffix: str) -> bool:
    yaml = build_yaml()

    try:
        original_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise HookError(f"file not found: {path}") from exc

    data = yaml.load(original_text)
    if not isinstance(data, CommentedMap):
        raise HookError(f"{path} must contain a top-level YAML mapping")

    changed = False
    for key, value in list(data.items()):
        if not isinstance(key, str):
            raise HookError(f"{path} contains non-string key {key!r}")
        if is_vault_value(value):
            continue
        if not isinstance(value, str):
            raise HookError(
                f"{path} key {key!r} must be a string or !vault value, got {type(value).__name__}"
            )
        data[key] = encrypt_value(
            key=key,
            value=value,
            vault_password_file=vault_password_file,
            encrypt_vault_id=encrypt_vault_id,
        )
        changed = True

    if changed:
        write_yaml(path, data, yaml)

    export_plaintext(path=path, data=data, vault_password_file=vault_password_file, plain_suffix=plain_suffix)
    return changed


def export_plaintext(path: Path, data: CommentedMap, vault_password_file: Path, plain_suffix: str) -> None:
    plain_data = CommentedMap()
    for key, value in data.items():
        if is_vault_value(value):
            plain_data[key] = decrypt_value(value, vault_password_file=vault_password_file)
        elif isinstance(value, str):
            plain_data[key] = value
        else:
            raise HookError(
                f"{path} key {key!r} must be a string or !vault value, got {type(value).__name__}"
            )

    plain_path = plaintext_path(path, plain_suffix)
    plain_yaml = build_yaml()
    write_yaml(plain_path, plain_data, plain_yaml)


def resolve_vault_password_file(args: argparse.Namespace, cwd: Path) -> Path:
    candidates: list[tuple[Path, Path]] = []
    if args.vault_password_file:
        candidates.append((Path(args.vault_password_file), cwd))

    env_password_file = os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
    if env_password_file:
        candidates.append((Path(env_password_file), cwd))

    cfg_path = resolve_ansible_cfg(args.ansible_cfg, cwd)
    if cfg_path:
        config_path = read_vault_password_file_from_cfg(cfg_path)
        if config_path:
            candidates.append((config_path, cfg_path.parent))

    for candidate, base in candidates:
        resolved = candidate.expanduser()
        if not resolved.is_absolute():
            resolved = (base / resolved).resolve()
        if resolved.is_file():
            return resolved

    raise HookError("could not resolve vault password file")


def resolve_ansible_cfg(arg_value: str | None, cwd: Path) -> Path | None:
    if arg_value:
        path = Path(arg_value).expanduser()
        return path.resolve() if path.exists() else None

    env_value = os.environ.get("ANSIBLE_CONFIG")
    if env_value:
        path = Path(env_value).expanduser()
        return path.resolve() if path.exists() else None

    local_cfg = cwd / "ansible.cfg"
    if local_cfg.exists():
        return local_cfg.resolve()

    return None


def read_vault_password_file_from_cfg(cfg_path: Path) -> Path | None:
    parser = configparser.ConfigParser()
    parser.read(cfg_path, encoding="utf-8")
    if not parser.has_option("defaults", "vault_password_file"):
        return None
    value = parser.get("defaults", "vault_password_file").strip()
    if not value:
        return None
    return Path(value).expanduser() if value.startswith("~") else Path(value)


def plaintext_path(path: Path, plain_suffix: str) -> Path:
    if path.suffix in {".yaml", ".yml"}:
        return path.with_name(f"{path.stem}{plain_suffix}{path.suffix}")
    return path.with_name(f"{path.name}{plain_suffix}")


def encrypt_value(key: str, value: str, vault_password_file: Path, encrypt_vault_id: str):
    command = [
        ansible_vault_bin(),
        "encrypt_string",
        "--vault-password-file",
        str(vault_password_file),
        "--encrypt-vault-id",
        encrypt_vault_id,
        "--stdin-name",
        key,
    ]
    result = run_command(command, input_text=value)
    yaml = build_yaml()
    parsed = yaml.load(result.stdout)
    if not isinstance(parsed, CommentedMap) or key not in parsed:
        raise HookError(f"failed to parse encrypted ansible-vault output for key {key!r}")
    return parsed[key]


def decrypt_value(value, vault_password_file: Path) -> str:
    ciphertext = str(value)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(ciphertext)
        temp_path = Path(handle.name)
    try:
        command = [
            ansible_vault_bin(),
            "view",
            "--vault-password-file",
            str(vault_password_file),
            str(temp_path),
        ]
        result = run_command(command)
        return result.stdout.rstrip("\n")
    finally:
        temp_path.unlink(missing_ok=True)


def ansible_vault_bin() -> str:
    return os.environ.get("ANSIBLE_VAULT_BIN", "ansible-vault")


def run_command(command: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise HookError(f"command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise HookError(message) from exc


def is_vault_value(value) -> bool:
    tag = getattr(value, "tag", None)
    if tag is None:
        return False
    return str(tag) == "!vault"


def build_yaml() -> YAML:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.explicit_start = True
    yaml.width = 4096
    return yaml


def write_yaml(path: Path, data: CommentedMap, yaml: YAML) -> None:
    buffer = io.StringIO()
    yaml.dump(data, buffer)
    path.write_text(buffer.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
