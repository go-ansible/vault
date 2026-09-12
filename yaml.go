package vault

import (
	"fmt"

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
	if err := decryptNodes(&root, password); err != nil {
		return err
	}
	// An empty document decodes to a zero node, which Decode rejects.
	if root.Kind == 0 {
		return nil
	}
	return root.Decode(out)
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
