package vault

import (
	"reflect"
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

// TestYAML11Bools pins PyYAML's implicit bool set, which real Ansible
// inherits and gopkg.in/yaml.v3 (a YAML 1.2 parser) does not. Every
// expectation here was MEASURED by running a playbook through real
// ansible-core 2.21.4 and printing `value | type_debug`, not read off
// the YAML 1.1 spec — which is how the bare y/n case was caught: the
// spec lists them, PyYAML does not resolve them.
func TestYAML11Bools(t *testing.T) {
	var got map[string]any
	if err := UnmarshalYAML([]byte(`
a_yes: yes
a_Yes: Yes
a_YES: YES
a_no: no
a_No: No
a_NO: NO
a_on: on
a_off: off
a_true: true
a_FALSE: FALSE
a_y: y
a_n: n
quoted: "yes"
single: 'no'
in_a_list: [yes, "yes", no]
nested: {k: on}
word: yesterday
`), "", &got); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key  string
		want any
	}{
		{"a_yes", true}, {"a_Yes", true}, {"a_YES", true},
		{"a_no", false}, {"a_No", false}, {"a_NO", false},
		{"a_on", true}, {"a_off", false},
		{"a_true", true}, {"a_FALSE", false},
		// PyYAML does NOT resolve bare y/n, whatever the spec says.
		{"a_y", "y"}, {"a_n", "n"},
		// Quoting is how a playbook asks for the word, in both YAML
		// versions — so both of these stay strings.
		{"quoted", "yes"}, {"single", "no"},
		// And a word that merely starts with one is untouched.
		{"word", "yesterday"},
	} {
		if got[tc.key] != tc.want {
			t.Errorf("%s = %#v, want %#v", tc.key, got[tc.key], tc.want)
		}
	}
	if want := []any{true, "yes", false}; !reflect.DeepEqual(got["in_a_list"], want) {
		t.Errorf("in_a_list = %#v, want %#v", got["in_a_list"], want)
	}
	if nested, _ := got["nested"].(map[string]any); nested == nil || nested["k"] != true {
		t.Errorf("nested = %#v, want k:true", got["nested"])
	}
}

// TestYAML11BoolsDoNotReachDecryptedSecrets: a !vault scalar decrypts
// to a string and real Ansible never re-resolves it, so a secret whose
// plaintext is "no" must stay the string "no" rather than becoming
// false. The resolution therefore runs BEFORE decryption, not after.
func TestYAML11BoolsDoNotReachDecryptedSecrets(t *testing.T) {
	doc := inlineDoc(t, "secret", "no", "pw")
	var got map[string]any
	if err := UnmarshalYAML([]byte(doc), "pw", &got); err != nil {
		t.Fatal(err)
	}
	if got["secret"] != "no" {
		t.Errorf("secret = %#v, want the string \"no\"", got["secret"])
	}
}

// TestYAML11Sexagesimal pins PyYAML's base-60 scalars against values
// produced by the REFERENCE interpreter, not by reading YAML 1.1.
// Real Ansible parses with PyYAML, so a duration written this way is
// a NUMBER there and was the string "1:30" here.
//
// The two resolvers differ in their FIRST group, which is easy to miss
// and changes the answer: an int may not start with 0 while a float
// may.
func TestYAML11Sexagesimal(t *testing.T) {
	var got map[string]any
	if err := UnmarshalYAML([]byte(`
a: 1:30
b: 1:30:30
c: -1:30
d: +1:30
e: 12:00
f: 190:20:30
g: 1:2:3
h: 1_0:30
i: 1:0
notint: 0:59
over59: 1:60
flt: 1:30.5
fltzero: 0:30.5
flttrail: 1:30.
plain: 59
quoted: "1:30"
word: a:30
`), "", &got); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key  string
		want any
	}{
		{"a", 90}, {"b", 5430}, {"c", -90}, {"d", 90},
		{"e", 720}, {"f", 685230}, {"g", 3723},
		{"h", 630}, // underscores are stripped, as they are in any YAML 1.1 int
		{"i", 60},
		// An INT may not start with 0, and no group may exceed 59.
		{"notint", "0:59"}, {"over59", "1:60"},
		{"flt", 90.5}, {"fltzero", 30.5}, {"flttrail", 90.0},
		{"plain", 59},
		// Quoting is how a playbook asks for the text, here as
		// everywhere.
		{"quoted", "1:30"}, {"word", "a:30"},
	} {
		if got[tc.key] != tc.want {
			t.Errorf("%s = %#v, want %#v", tc.key, got[tc.key], tc.want)
		}
	}
}
