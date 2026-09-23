package vault

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML decodes YAML that may carry secrets in either of the two
// shapes real Ansible accepts, and decodes into out exactly as
// yaml.Unmarshal would otherwise.
//
//   - the whole file encrypted, as ansible-vault encrypt leaves it;
//
//   - individual !vault-tagged scalars inside an otherwise-plaintext
//     file, as ansible-vault encrypt_string produces:
//
//     db_password: !vault |
//     $ANSIBLE_VAULT;1.1;AES256
//     3865...
//
// The second shape is what lets one secret live in a vars file everybody
// can read. Each tagged scalar is decrypted in place before decoding, so
// the caller gets a plain value and never sees the ciphertext.
//
// A missing password is an error only if something actually needs
// decrypting, so a plaintext file still loads with no password at all.
func UnmarshalYAML(data []byte, password string, out any) error {
	plain, err := MaybeDecrypt(data, password)
	if err != nil {
		return err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(plain, &root); err != nil {
		return err
	}
	// BEFORE decrypting, deliberately: a !vault scalar decrypts to a
	// string and real Ansible never re-resolves it, so a secret whose
	// plaintext happens to be "no" must stay the string "no".
	resolveYAML11Bools(&root)
	if err := decryptNodes(&root, password); err != nil {
		return err
	}
	// An empty document decodes to a zero node, which Decode rejects.
	if root.Kind == 0 {
		return nil
	}
	return root.Decode(out)
}

// yaml11Bools is PyYAML's own implicit bool resolver, which real
// Ansible inherits — its pattern read straight out of
// yaml.resolver.Resolver at runtime rather than copied from the spec:
//
//	yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF
//
// Note what is NOT there: bare y and n. PyYAML leaves those as
// strings, and so does this — confirmed by running a playbook rather
// than by reading the YAML 1.1 spec, which does list them.
var yaml11Bools = map[string]bool{
	"yes": true, "Yes": true, "YES": true,
	"no": false, "No": false, "NO": false,
	"true": true, "True": true, "TRUE": true,
	"false": false, "False": false, "FALSE": false,
	"on": true, "On": true, "ON": true,
	"off": false, "Off": false, "OFF": false,
}

// resolveYAML11Bools retags every PLAIN (unquoted) scalar that PyYAML
// would read as a boolean. gopkg.in/yaml.v3 implements YAML 1.2, whose
// core schema knows only true/false, so "yes" arrived as the string
// "yes" where real Ansible has the boolean True.
//
// That is not cosmetic. `when: some_flag` with `some_flag: yes` FAILED
// here — "Conditional result was derived from value of type str" —
// on a playbook real Ansible runs, and any module argument written
// `force: yes` reached the module as a string.
//
// Quoted scalars are left alone, which is the whole point of the
// style check: "yes" and 'yes' are strings in both YAML versions, and
// that is how a playbook asks for the word.
func resolveYAML11Bools(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode {
		if n.Tag == "!!str" && n.Style == 0 {
			if b, ok := yaml11Bools[n.Value]; ok {
				n.Tag = "!!bool"
				// Normalised rather than left as "yes": yaml.v3's own
				// bool decoder is a YAML 1.2 one and need not accept
				// every spelling we just admitted.
				n.Value = strconv.FormatBool(b)
			}
		}
		return
	}
	for _, child := range n.Content {
		resolveYAML11Bools(child)
	}
}

// vaultTag is the YAML tag real Ansible marks an encrypted scalar with.
const vaultTag = "!vault"

// decryptNodes replaces every !vault-tagged scalar in the tree with its
// plaintext, turning it back into an ordinary string node.
func decryptNodes(n *yaml.Node, password string) error {
	if n.Kind == yaml.ScalarNode && n.Tag == vaultTag {
		if password == "" {
			return fmt.Errorf("vault: a !vault value needs a vault password (line %d)", n.Line)
		}
		plain, err := Decrypt(n.Value, password)
		if err != nil {
			return fmt.Errorf("vault: !vault value at line %d: %w", n.Line, err)
		}
		n.Tag = "!!str"
		n.Value = string(plain)
		n.Style = 0
		return nil
	}
	for _, child := range n.Content {
		if err := decryptNodes(child, password); err != nil {
			return err
		}
	}
	return nil
}
