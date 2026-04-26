# pre-commit-ansible-vault-encrypt-string

Pre-commit hook for repositories that keep `*_vault.yaml` files in Git with visible key names and per-value Ansible Vault encryption.

The hook enforces this workflow:

- version `*_vault.yaml`
- keep all top-level values encrypted with `ansible-vault encrypt_string`
- export a decrypted mirror next to each file as `*_vault.plain.yaml`
- keep `*_vault.plain.yaml` out of Git

If the hook rewrites a vault file, it exits with code `1` so the updated file can be staged deliberately.

## Supported file shape

Each `*_vault.yaml` file must be a top-level YAML mapping whose values are strings.

Example:

```yaml
vault_wifi_main_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  6131
vault_wifi_guest_password: guest-password
```

After the hook runs, all values are encrypted and `*_vault.plain.yaml` is refreshed.

## Install in pre-commit

```yaml
repos:
  - repo: https://github.com/your-org/pre-commit-ansible-vault-encrypt-string
    rev: v0.1.0
    hooks:
      - id: ansible-vault-encrypt-string
```

Optional arguments:

```yaml
      - id: ansible-vault-encrypt-string
        args:
          - --vault-password-file=~/.vault_pass
          - --ansible-cfg=ansible.cfg
          - --plain-suffix=.plain
```

## Password lookup order

1. `--vault-password-file`
2. `ANSIBLE_VAULT_PASSWORD_FILE`
3. `ansible.cfg`

When reading `ansible.cfg`, the hook uses:

1. `--ansible-cfg` if provided
2. `ANSIBLE_CONFIG` if set
3. `./ansible.cfg`

The hook reads `vault_password_file` from `[defaults]` and currently supports file paths only.

## Git ignore

Add this to your repository:

```gitignore
*_vault.plain.yaml
```

## Exit behavior

- `0`: nothing changed
- `1`: vault files were rewritten or a validation error occurred

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .[test]
pytest
```
