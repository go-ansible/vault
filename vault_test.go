package vault

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		plaintext string
		password  string
	}{
		{"short", "hello", "secret"},
		{"empty", "", "secret"},
		{"exact block", strings.Repeat("x", 16), "secret"},
		{"multi block", strings.Repeat("ansible vault test data\n", 20), "correct horse battery staple"},
		{"unicode", "café ☂ 日本語", "élan"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc, err := Encrypt([]byte(c.plaintext), c.password, "")
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if !IsVault([]byte(enc)) {
				t.Fatalf("IsVault reports false on our own output")
			}
			dec, err := Decrypt(enc, c.password)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(dec) != c.plaintext {
				t.Fatalf("round trip mismatch: got %q want %q", dec, c.plaintext)
			}
		})
	}
}

func TestWrongPassword(t *testing.T) {
	enc, err := Encrypt([]byte("secret data"), "correct", "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(enc, "wrong"); err != ErrHMACMismatch {
		t.Fatalf("Decrypt with wrong password: got %v, want ErrHMACMismatch", err)
	}
}

func TestVaultID(t *testing.T) {
	enc, err := Encrypt([]byte("x"), "pw", "prod")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	id, err := VaultID(enc)
	if err != nil {
		t.Fatalf("VaultID: %v", err)
	}
	if id != "prod" {
		t.Fatalf("VaultID = %q, want %q", id, "prod")
	}
}

func TestNotVault(t *testing.T) {
	if IsVault([]byte("plain: yaml\n")) {
		t.Fatal("IsVault reports true on plain YAML")
	}
	if _, err := Decrypt("plain: yaml\n", "pw"); err != ErrNotVault {
		t.Fatalf("Decrypt on non-vault: got %v, want ErrNotVault", err)
	}
}

func TestLineWrap(t *testing.T) {
	enc, err := Encrypt([]byte(strings.Repeat("y", 500)), "pw", "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	lines := strings.Split(strings.TrimRight(enc, "\n"), "\n")
	for i, l := range lines[1:] { // skip header line
		if len(l) > lineWrap {
			t.Fatalf("body line %d is %d chars, want <= %d", i, len(l), lineWrap)
		}
	}
}

// ansibleVault locates a real ansible-vault binary for cross-validation
// against this package's own implementation. Tests using it skip cleanly
// when none is available (e.g. in CI, which does not install Python).
func ansibleVault(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("ANSIBLE_VAULT_BIN"); p != "" {
		return p
	}
	p, err := exec.LookPath("ansible-vault")
	if err != nil {
		t.Skip("ansible-vault not found in PATH; skipping cross-validation against the reference implementation")
	}
	return p
}

// TestInteropDecryptReference encrypts with the real ansible-vault and
// decrypts with this package, byte for byte.
func TestInteropDecryptReference(t *testing.T) {
	bin := ansibleVault(t)
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("interop-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "secret.yml")
	plaintext := "db_password: hunter2\nother: [1, 2, 3]\n"
	if err := os.WriteFile(target, []byte(plaintext), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "encrypt", "--vault-password-file", pwFile, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt: %v\n%s", err, out)
	}
	encrypted, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(string(encrypted), "interop-secret")
	if err != nil {
		t.Fatalf("our Decrypt of reference-encrypted file: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("interop decrypt mismatch: got %q want %q", got, plaintext)
	}
}

// TestInteropEncryptReference encrypts with this package and decrypts
// with the real ansible-vault, byte for byte.
func TestInteropEncryptReference(t *testing.T) {
	bin := ansibleVault(t)
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("other-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext := "api_key: abc123\nnested:\n  key: value\n"
	enc, err := Encrypt([]byte(plaintext), "other-secret", "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	target := filepath.Join(dir, "ours.yml")
	if err := os.WriteFile(target, []byte(enc), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "decrypt", "--vault-password-file", pwFile, "--output", "-", target)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-vault decrypt: %v", err)
	}
	if !bytes.Equal(out, []byte(plaintext)) {
		t.Fatalf("reference decrypt of our output mismatch: got %q want %q", out, plaintext)
	}
}
