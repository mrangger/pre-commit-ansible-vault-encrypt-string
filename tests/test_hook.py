from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = "pre_commit_ansible_vault_encrypt_string.main"


def write_fake_ansible_vault(bin_path: Path) -> None:
    bin_path.write_text(
        """#!/usr/bin/env python3
import sys
from pathlib import Path


def main():
    args = sys.argv[1:]
    if not args:
        raise SystemExit(2)

    if args[0] == 'encrypt_string':
        key = args[args.index('--stdin-name') + 1]
        plaintext = sys.stdin.read()
        payload = plaintext.encode('utf-8').hex()
        sys.stdout.write(f"{key}: !vault |\\n  $ANSIBLE_VAULT;1.1;AES256\\n  {payload}\\n")
        return

    if args[0] == 'view':
        content = Path(args[-1]).read_text(encoding='utf-8').splitlines()
        payload = ''.join(line.strip() for line in content[1:])
        sys.stdout.write(bytes.fromhex(payload).decode('utf-8'))
        return

    raise SystemExit(2)


if __name__ == '__main__':
    main()
""",
        encoding="utf-8",
    )
    bin_path.chmod(0o755)


def run_hook(tmp_path: Path, *files: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", MODULE, *files],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


def test_rewrites_plaintext_and_exports_plain_mirror(tmp_path: Path) -> None:
    fake_bin = tmp_path / "ansible-vault"
    write_fake_ansible_vault(fake_bin)
    vault_pass = tmp_path / ".vault_pass"
    vault_pass.write_text("secret\n", encoding="utf-8")
    (tmp_path / "ansible.cfg").write_text("[defaults]\nvault_password_file = .vault_pass\n", encoding="utf-8")

    vault_file = tmp_path / "accesspoints_vault.yaml"
    vault_file.write_text(
        """---
wifi_main: supersecret
wifi_guest: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  6775657374
""",
        encoding="utf-8",
    )

    result = run_hook(
        tmp_path,
        str(vault_file.name),
        extra_env={"ANSIBLE_VAULT_BIN": str(fake_bin)},
    )

    assert result.returncode == 1
    updated = vault_file.read_text(encoding="utf-8")
    assert "wifi_main: !vault |" in updated
    assert "7375706572736563726574" in updated

    plain_file = tmp_path / "accesspoints_vault.plain.yaml"
    plain = plain_file.read_text(encoding="utf-8")
    assert "wifi_main: supersecret" in plain
    assert "wifi_guest: guest" in plain


def test_returns_zero_when_everything_already_encrypted(tmp_path: Path) -> None:
    fake_bin = tmp_path / "ansible-vault"
    write_fake_ansible_vault(fake_bin)
    vault_pass = tmp_path / ".vault_pass"
    vault_pass.write_text("secret\n", encoding="utf-8")

    vault_file = tmp_path / "router_vault.yaml"
    vault_file.write_text(
        """---
secret_one: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  666f6f
secret_two: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  626172
""",
        encoding="utf-8",
    )

    result = run_hook(
        tmp_path,
        str(vault_file.name),
        extra_env={
            "ANSIBLE_VAULT_BIN": str(fake_bin),
            "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
        },
    )

    assert result.returncode == 0
    plain_file = tmp_path / "router_vault.plain.yaml"
    assert plain_file.exists()
    assert "secret_one: foo" in plain_file.read_text(encoding="utf-8")


def test_rejects_non_string_values(tmp_path: Path) -> None:
    fake_bin = tmp_path / "ansible-vault"
    write_fake_ansible_vault(fake_bin)
    vault_pass = tmp_path / ".vault_pass"
    vault_pass.write_text("secret\n", encoding="utf-8")

    vault_file = tmp_path / "bad_vault.yaml"
    vault_file.write_text(
        """---
bad_secret:
  nested: value
""",
        encoding="utf-8",
    )

    result = run_hook(
        tmp_path,
        str(vault_file.name),
        extra_env={
            "ANSIBLE_VAULT_BIN": str(fake_bin),
            "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
        },
    )

    assert result.returncode == 1
    assert "must be a string or !vault value" in result.stderr


def test_reads_password_file_from_ansible_cfg(tmp_path: Path) -> None:
    fake_bin = tmp_path / "ansible-vault"
    write_fake_ansible_vault(fake_bin)
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "vault-pass").write_text("secret\n", encoding="utf-8")
    (tmp_path / "ansible.cfg").write_text(
        "[defaults]\nvault_password_file = secrets/vault-pass\n",
        encoding="utf-8",
    )

    vault_file = tmp_path / "wifi_vault.yaml"
    vault_file.write_text("---\nwifi_main: open\n", encoding="utf-8")

    result = run_hook(
        tmp_path,
        str(vault_file.name),
        extra_env={"ANSIBLE_VAULT_BIN": str(fake_bin)},
    )

    assert result.returncode == 1
    assert (tmp_path / "wifi_vault.plain.yaml").exists()
