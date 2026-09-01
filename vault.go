// Package vault implements the Ansible Vault 1.1 file format: AES-256 in
// CTR mode with a PBKDF2-HMAC-SHA256 derived key and an encrypt-then-MAC
// HMAC-SHA256 authentication tag, hex-wrapped at 80 columns.
//
// The wire format is fixed by the reference implementation
// (ansible.parsing.vault.VaultAES256 in ansible-core) and is reproduced
// here byte-for-byte so files written by this package decrypt with the
// real `ansible-vault` and vice versa.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Header is the first line of every vault-encrypted file or inline blob.
const headerPrefix = "$ANSIBLE_VAULT"

const (
	formatVersion = "1.1"
	cipherName    = "AES256"

	saltLength   = 32
	keyLength    = 32 // AES-256 key
	ivLength     = 16 // AES block size
	pbkdf2Rounds = 10000

	lineWrap = 80
)

// ErrNotVault is returned when the input does not carry a recognized
// vault header.
var ErrNotVault = errors.New("vault: not an ansible-vault payload")

// ErrHMACMismatch is returned when decryption's integrity check fails —
// almost always a wrong password.
var ErrHMACMismatch = errors.New("vault: HMAC verification failed (wrong password?)")

// IsVault reports whether data begins with a recognized vault header,
// with or without a leading vault-id.
func IsVault(data []byte) bool {
	line := firstLine(data)
	return strings.HasPrefix(line, headerPrefix+";")
}

func firstLine(data []byte) string {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return string(data[:i])
	}
	return string(data)
}

// Encrypt encrypts plaintext under password and returns the full vault
// text (header line + 80-column-wrapped hex body), ready to write to a
// file or embed as a YAML block scalar.
//
// vaultID, if non-empty, is appended to the header
// ($ANSIBLE_VAULT;1.1;AES256;vaultID) exactly as `ansible-vault
// --vault-id` does.
func Encrypt(plaintext []byte, password string, vaultID string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("vault: generating salt: %w", err)
	}
	return encryptWithSalt(plaintext, password, vaultID, salt)
}

func encryptWithSalt(plaintext []byte, password string, vaultID string, salt []byte) (string, error) {
	key1, key2, iv := deriveKeys([]byte(password), salt)

	padded := pkcs7Pad(plaintext, aes.BlockSize)

	block, err := aes.NewCipher(key1)
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, padded)

	mac := hmac.New(sha256.New, key2)
	mac.Write(ciphertext)
	hmacHex := hex.EncodeToString(mac.Sum(nil))

	inner := hex.EncodeToString(salt) + "\n" + hmacHex + "\n" + hex.EncodeToString(ciphertext)
	outer := hex.EncodeToString([]byte(inner))

	header := headerPrefix + ";" + formatVersion + ";" + cipherName
	if vaultID != "" {
		header += ";" + vaultID
	}
	return header + "\n" + wrap(outer, lineWrap), nil
}

// Decrypt decrypts a full vault text (as produced by Encrypt, or by
// `ansible-vault encrypt`) with password.
func Decrypt(vaultText string, password string) ([]byte, error) {
	header, body, err := splitHeader(vaultText)
	if err != nil {
		return nil, err
	}
	if header.cipher != cipherName {
		return nil, fmt.Errorf("vault: unsupported cipher %q (only AES256 is implemented)", header.cipher)
	}

	outer := strings.Join(strings.Fields(body), "")
	inner, err := hex.DecodeString(outer)
	if err != nil {
		return nil, fmt.Errorf("vault: malformed body: %w", err)
	}
	parts := strings.SplitN(string(inner), "\n", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault: malformed body: expected salt/hmac/ciphertext, got %d parts", len(parts))
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("vault: malformed salt: %w", err)
	}
	wantHMAC := parts[1]
	ciphertext, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault: malformed ciphertext: %w", err)
	}

	key1, key2, iv := deriveKeys([]byte(password), salt)

	mac := hmac.New(sha256.New, key2)
	mac.Write(ciphertext)
	gotHMAC := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(wantHMAC), []byte(gotHMAC)) != 1 {
		return nil, ErrHMACMismatch
	}

	block, err := aes.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(padded, ciphertext)

	return pkcs7Unpad(padded, aes.BlockSize)
}

// header is the parsed first line of a vault text.
type header struct {
	version string
	cipher  string
	vaultID string
}

func splitHeader(vaultText string) (header, string, error) {
	nl := strings.IndexByte(vaultText, '\n')
	var line, rest string
	if nl < 0 {
		line, rest = vaultText, ""
	} else {
		line, rest = vaultText[:nl], vaultText[nl+1:]
	}
	fields := strings.Split(strings.TrimSpace(line), ";")
	if len(fields) < 3 || fields[0] != headerPrefix {
		return header{}, "", ErrNotVault
	}
	h := header{version: fields[1], cipher: fields[2]}
	if len(fields) >= 4 {
		h.vaultID = fields[3]
	}
	return h, rest, nil
}

// deriveKeys reproduces VaultAES256._gen_key_initctr: PBKDF2-HMAC-SHA256,
// 10000 rounds, 2*32+16 = 80 derived bytes split into the AES key, the
// HMAC key, and the CTR initial counter block.
func deriveKeys(password, salt []byte) (aesKey, hmacKey, iv []byte) {
	derived := pbkdf2.Key(password, salt, pbkdf2Rounds, 2*keyLength+ivLength, sha256.New)
	return derived[:keyLength], derived[keyLength : 2*keyLength], derived[2*keyLength : 2*keyLength+ivLength]
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(append([]byte{}, data...), pad...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	n := len(data)
	if n == 0 || n%blockSize != 0 {
		return nil, errors.New("vault: invalid padded length")
	}
	padLen := int(data[n-1])
	if padLen == 0 || padLen > blockSize || padLen > n {
		return nil, errors.New("vault: invalid PKCS7 padding")
	}
	for _, b := range data[n-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("vault: invalid PKCS7 padding")
		}
	}
	return data[:n-padLen], nil
}

func wrap(s string, width int) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteByte('\n')
		s = s[width:]
	}
	b.WriteString(s)
	b.WriteByte('\n')
	return b.String()
}

// VaultID returns the vault-id label carried by a vault text's header
// (the part after the cipher name), or "" if none was set.
func VaultID(vaultText string) (string, error) {
	h, _, err := splitHeader(vaultText)
	if err != nil {
		return "", err
	}
	return h.vaultID, nil
}

// FormatVersion reports the vault format version string ("1.1" for
// everything this package produces or reads).
func FormatVersion(vaultText string) (string, error) {
	h, _, err := splitHeader(vaultText)
	if err != nil {
		return "", err
	}
	return h.version, nil
}
