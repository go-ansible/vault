package vault

import (
	"strings"
	"testing"
)

// inlineDoc builds the shape ansible-vault encrypt_string produces: a
// !vault-tagged block scalar under a key, beside ordinary plaintext.
func inlineDoc(t *testing.T, name, secret, password string) string {
	t.Helper()
	enc, err := Encrypt([]byte(secret), password, "")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(name + ": !vault |\n")
	for _, line := range strings.Split(strings.TrimRight(enc, "\n"), "\n") {
		b.WriteString("          " + line + "\n")
	}
	b.WriteString("plain_key: visible\n")
	return b.String()
}

func TestUnmarshalYAMLInlineVaultScalar(t *testing.T) {
	doc := inlineDoc(t, "secret", "s3cr3t", "pw")

	var out map[string]any
	if err := UnmarshalYAML([]byte(doc), "pw", &out); err != nil {
		t.Fatal(err)
	}
	if out["secret"] != "s3cr3t" {
		t.Errorf("secret = %#v, want the decrypted value", out["secret"])
	}
	// The rest of the file is ordinary YAML and must come through as-is.
	if out["plain_key"] != "visible" {
		t.Errorf("plain_key = %#v, want visible", out["plain_key"])
	}

	// Without the password, a clear error naming the line — not the
	// ciphertext handed back as if it were the value.
	var again map[string]any
	err := UnmarshalYAML([]byte(doc), "", &again)
	if err == nil {
		t.Fatal("no password on a !vault value: got nil error, want one")
	}
	if !strings.Contains(err.Error(), "vault password") {
		t.Errorf("error = %v, want it to mention the vault password", err)
	}

	// A wrong password fails rather than yielding rubbish.
	if err := UnmarshalYAML([]byte(doc), "wrong", &again); err == nil {
		t.Error("wrong password: got nil error, want one")
	}
}

// TestUnmarshalYAMLNested covers a tagged scalar that is not at the top
// level, since the walk has to reach into mappings and sequences.
func TestUnmarshalYAMLNested(t *testing.T) {
	inner := inlineDoc(t, "pass", "deep", "pw")
	var doc strings.Builder
	doc.WriteString("db:\n")
	for _, line := range strings.Split(strings.TrimRight(inner, "\n"), "\n") {
		doc.WriteString("  " + line + "\n")
	}

	var out map[string]any
	if err := UnmarshalYAML([]byte(doc.String()), "pw", &out); err != nil {
		t.Fatal(err)
	}
	db, ok := out["db"].(map[string]any)
	if !ok {
		t.Fatalf("db = %#v, want a mapping", out["db"])
	}
	if db["pass"] != "deep" {
		t.Errorf("db.pass = %#v, want deep", db["pass"])
	}
}

// TestUnmarshalYAMLWholeFileAndPlaintext covers the other two shapes: a
// file encrypted in its entirety, and one with no secrets at all, which
// must load with no password.
func TestUnmarshalYAMLWholeFileAndPlaintext(t *testing.T) {
	whole, err := Encrypt([]byte("a: 1\n"), "pw", "")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := UnmarshalYAML([]byte(whole), "pw", &out); err != nil {
		t.Fatal(err)
	}
	if out["a"] != 1 {
		t.Errorf("a = %#v, want 1", out["a"])
	}

	out = nil
	if err := UnmarshalYAML([]byte("b: 2\n"), "", &out); err != nil {
		t.Fatalf("plaintext with no password: %v", err)
	}
	if out["b"] != 2 {
		t.Errorf("b = %#v, want 2", out["b"])
	}

	// An empty document is not an error.
	var empty map[string]any
	if err := UnmarshalYAML(nil, "", &empty); err != nil {
		t.Errorf("empty document: %v", err)
	}
}
