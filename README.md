# vault

Ansible Vault-compatible AES256 encryption for secrets, pure Go CGO=0.

Part of [go-ansible](https://github.com/go-ansible) — a pure-Go (CGO=0),
functional-parity port of [Ansible](https://www.ansible.com/).

[![CI](https://github.com/go-ansible/vault/actions/workflows/ci.yml/badge.svg)](https://github.com/go-ansible/vault/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-ansible/vault.svg)](https://pkg.go.dev/github.com/go-ansible/vault)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

## Usage

```go
data, _ := os.ReadFile("secrets.yml")
if vault.IsVault(data) {
    plaintext, err := vault.Decrypt(string(data), password)
    // ...
}

ciphertext, err := vault.Encrypt(plaintext, password, "" /* vault ID, optional */)
```

`VaultID` and `FormatVersion` read a vault-encrypted string's header (`$ANSIBLE_VAULT;1.1;AES256`)
without decrypting the body — useful for routing a secret to the right password
before attempting to open it.
