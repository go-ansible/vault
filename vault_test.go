package vault

import (
	"bytes"
	"encoding/hex"
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

func TestIsVaultNoTrailingNewline(t *testing.T) {
	// firstLine's no-'\n'-found branch: the whole input is the header.
	if !IsVault([]byte(headerPrefix + ";1.1;AES256")) {
		t.Fatal("IsVault reports false on a header-only payload with no trailing newline")
	}
}

func TestSplitHeaderNoNewline(t *testing.T) {
	// splitHeader's nl<0 branch: a vault text that is only a header line,
	// with no body and no trailing newline.
	id, err := VaultID(headerPrefix + ";1.1;AES256;myvault")
	if err != nil {
		t.Fatalf("VaultID: %v", err)
	}
	if id != "myvault" {
		t.Fatalf("VaultID = %q, want %q", id, "myvault")
	}
}

func TestSplitHeaderTooFewFields(t *testing.T) {
	if _, err := VaultID(headerPrefix + ";1.1"); err != ErrNotVault {
		t.Fatalf("VaultID on header with too few fields: got %v, want ErrNotVault", err)
	}
}

func TestVaultIDError(t *testing.T) {
	if _, err := VaultID("plain: yaml\n"); err != ErrNotVault {
		t.Fatalf("VaultID on non-vault: got %v, want ErrNotVault", err)
	}
}

func TestFormatVersion(t *testing.T) {
	enc, err := Encrypt([]byte("x"), "pw", "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	v, err := FormatVersion(enc)
	if err != nil {
		t.Fatalf("FormatVersion: %v", err)
	}
	if v != "1.1" {
		t.Fatalf("FormatVersion = %q, want %q", v, "1.1")
	}
	if _, err := FormatVersion("plain: yaml\n"); err != ErrNotVault {
		t.Fatalf("FormatVersion on non-vault: got %v, want ErrNotVault", err)
	}
}

func TestDecryptMalformed(t *testing.T) {
	header := headerPrefix + ";1.1;AES256"

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unsupported cipher",
			body: "",
			want: "unsupported cipher",
		},
		{
			name: "invalid outer hex",
			body: "not-valid-hex!!",
			want: "malformed body",
		},
		{
			name: "wrong part count",
			body: hex.EncodeToString([]byte("justonepart")),
			want: "expected salt/hmac/ciphertext",
		},
		{
			name: "malformed salt",
			body: hex.EncodeToString([]byte("nothexsalt\ndeadbeef\ncafebabe")),
			want: "malformed salt",
		},
		{
			name: "malformed ciphertext",
			body: hex.EncodeToString([]byte(hex.EncodeToString([]byte{0x01, 0x02}) + "\n" + "dummyhmac" + "\n" + "zz-not-hex")),
			want: "malformed ciphertext",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hdr := header
			if c.name == "unsupported cipher" {
				hdr = headerPrefix + ";1.1;AES128"
			}
			text := hdr + "\n" + c.body + "\n"
			_, err := Decrypt(text, "pw")
			if err == nil {
				t.Fatalf("Decrypt(%q): got nil error, want one containing %q", text, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Decrypt(%q): err = %q, want it to contain %q", text, err, c.want)
			}
		})
	}
}

func TestPkcs7Unpad(t *testing.T) {
	cases := []struct {
		name      string
		data      []byte
		blockSize int
		wantErr   bool
		want      string
	}{
		{"empty", nil, 16, true, ""},
		{"not a multiple of block size", []byte("123456789012345"), 16, true, ""}, // 15 bytes
		{"pad length zero", append([]byte("0123456789012345"[:15]), 0x00), 16, true, ""},
		{"pad length exceeds block size", append([]byte("0123456789012345"[:15]), 0x11), 16, true, ""},
		{"pad bytes inconsistent", append([]byte("01234567890"), 0x01, 0x02, 0x03, 0x04, 0x05), 16, true, ""},
		{"valid padding", append([]byte("hello"), 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b), 16, false, "hello"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := pkcs7Unpad(c.data, c.blockSize)
			if c.wantErr {
				if err == nil {
					t.Fatalf("pkcs7Unpad(%v, %d): got nil error, want one", c.data, c.blockSize)
				}
				return
			}
			if err != nil {
				t.Fatalf("pkcs7Unpad(%v, %d): %v", c.data, c.blockSize, err)
			}
			if string(got) != c.want {
				t.Fatalf("pkcs7Unpad = %q, want %q", got, c.want)
			}
		})
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
