package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// AES-CTR is MALLEABLE: ciphertext is plaintext XOR a keystream, so
// flipping a ciphertext bit flips exactly the corresponding plaintext
// bit. Nothing about the cipher stops someone with write access to an
// encrypted file -- a repository, a backup, a clone in flight -- from
// making a chosen, surgical edit to a secret they cannot read.
//
// The HMAC is the only thing that stops it, and these tests exist to
// prove it is load-bearing rather than decorative.

const tamperPassword = "correct horse"

// policy is written so that a single bit flip turns the answer over:
// '0' is 0x30 and '1' is 0x31, so XOR 0x01 at that one byte is the
// whole attack.
const policy = "permit_root_login: 0\n"

func vaultFields(t *testing.T, text string) (salt []byte, macHex string, ciphertext []byte) {
	t.Helper()
	_, body, err := splitHeader(text)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := hex.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(inner), "\n", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(parts))
	}
	if salt, err = hex.DecodeString(parts[0]); err != nil {
		t.Fatal(err)
	}
	if ciphertext, err = hex.DecodeString(parts[2]); err != nil {
		t.Fatal(err)
	}
	return salt, parts[1], ciphertext
}

func assembleVault(salt []byte, macHex string, ciphertext []byte) string {
	inner := hex.EncodeToString(salt) + "\n" + macHex + "\n" + hex.EncodeToString(ciphertext)
	return headerPrefix + ";" + formatVersion + ";" + cipherName + "\n" +
		hex.EncodeToString([]byte(inner)) + "\n"
}

// flipPolicyBit returns the ciphertext with the byte covering the '0' in
// policy XORed by 0x01 -- turning the decrypted value into '1'.
func flipPolicyBit(ciphertext []byte) []byte {
	out := append([]byte{}, ciphertext...)
	out[strings.IndexByte(policy, '0')] ^= 0x01
	return out
}

// CONTROL: the flip really does rewrite the plaintext, in exactly the
// way an attacker would want. Without this, the refusal tests below
// could pass because the tamper was a no-op, which would prove nothing
// about the HMAC at all.
func TestTheBitFlipReallyRewritesThePolicy(t *testing.T) {
	enc, err := Encrypt([]byte(policy), tamperPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	salt, _, ciphertext := vaultFields(t, enc)
	tampered := flipPolicyBit(ciphertext)

	// Re-authenticate the tampered ciphertext, which is precisely what
	// an attacker CANNOT do without the password -- here it stands in
	// for "suppose the HMAC check were bypassed".
	_, hmacKey, _ := deriveKeys([]byte(tamperPassword), salt)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(tampered)

	got, err := Decrypt(assembleVault(salt, hex.EncodeToString(mac.Sum(nil)), tampered), tamperPassword)
	if err != nil {
		t.Fatalf("control could not decrypt its own re-authenticated tamper: %v", err)
	}
	if want := "permit_root_login: 1\n"; string(got) != want {
		t.Fatalf("the flip is NOT an effective tamper: got %q, want %q — "+
			"the refusal tests below would prove nothing", got, want)
	}
	t.Logf("CONTROL: one flipped bit turns %q into %q", policy, got)
}

func TestATamperedVaultIsRefused(t *testing.T) {
	enc, err := Encrypt([]byte(policy), tamperPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	salt, macHex, ciphertext := vaultFields(t, enc)

	for _, c := range []struct {
		name string
		text string
	}{
		{"a flipped ciphertext bit", assembleVault(salt, macHex, flipPolicyBit(ciphertext))},
		{"a flipped salt bit", assembleVault(append([]byte{salt[0] ^ 0x01}, salt[1:]...), macHex, ciphertext)},
		{"a flipped HMAC bit", assembleVault(salt, flipHex(macHex), ciphertext)},
		{"a truncated ciphertext", assembleVault(salt, macHex, ciphertext[:len(ciphertext)-aesBlock])},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Decrypt(c.text, tamperPassword)
			if err != ErrHMACMismatch {
				t.Errorf("tampering was not refused: err=%v, plaintext=%q — want ErrHMACMismatch", err, got)
			}
		})
	}
}

const aesBlock = 16

// flipHex flips the low bit of the first nibble of a hex string.
func flipHex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return s
	}
	b[0] ^= 0x01
	return hex.EncodeToString(b)
}

// A correct password must still work after all that, so the tests above
// cannot be passing because Decrypt simply refuses everything.
func TestAnUntamperedVaultStillDecrypts(t *testing.T) {
	enc, err := Encrypt([]byte(policy), tamperPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(enc, tamperPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(policy)) {
		t.Fatalf("round trip changed the data: %q", got)
	}
}
