// SPDX-License-Identifier: ISC

package e521

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// Verify must refuse each signature below. They come from testdata/oracle.py
// (see testdata/make_vectors.py), which follows RFC 8032 section 5.2 and ITI
// DOC-ICP-01.01 section 2; each vector names the rule it breaks.
type negativeVectors struct {
	Signatures []struct {
		Name      string `json:"name"`
		Public    string `json:"public"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
		Rule      string `json:"rule"`
	} `json:"signatures"`
	Keys []struct {
		Name   string `json:"name"`
		Public string `json:"public"`
		Rule   string `json:"rule"`
	} `json:"keys"`
}

func readNegative(t *testing.T) negativeVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/ed521-negative.json")
	if err != nil {
		t.Fatal(err)
	}
	var v negativeVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyRejectsOracleNegativeVectors(t *testing.T) {
	v := readNegative(t)
	if len(v.Signatures) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Signatures {
		x, y := E521().DecompressPoint(mustHex(t, c.Public))
		if x == nil || y == nil {
			t.Errorf("%s: the public key does not decompress", c.Name)
			continue
		}
		if NewPublicKey(x, y).Verify(mustHex(t, c.Message), mustHex(t, c.Signature)) {
			t.Errorf("%s: Verify accepts it (%s)", c.Name, c.Rule)
		}
	}
}

func TestDecompressPointRejectsOracleNegativeKeys(t *testing.T) {
	for _, c := range readNegative(t).Keys {
		if x, y := E521().DecompressPoint(mustHex(t, c.Public)); x != nil || y != nil {
			t.Errorf("%s: DecompressPoint accepts it (%s)", c.Name, c.Rule)
		}
	}
}

func negativeSigner(t *testing.T) (*PrivateKey, *PublicKey, []byte, []byte) {
	t.Helper()
	d, _ := new(big.Int).SetString(testScalar, 16)
	priv := &PrivateKey{D: d, curve: E521()}
	msg := []byte("Test message for digital signature")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.GetPublic()
	if !pub.Verify(msg, sig) {
		t.Fatal("control: Verify rejects the signature Sign made")
	}
	return priv, pub, msg, sig
}

// Every octet of the 132 of a signature is bound: a bit flipped in any one of
// them makes Verify fail.
func TestVerifyRejectsEverySingleOctetChange(t *testing.T) {
	_, pub, msg, sig := negativeSigner(t)
	for i := range sig {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 0x01
		if pub.Verify(msg, bad) {
			t.Fatalf("Verify accepts the signature with octet %d changed", i)
		}
	}
}

func TestVerifyRejectsWrongKeyMessageAndLength(t *testing.T) {
	priv, pub, msg, sig := negativeSigner(t)

	other, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if other.GetPublic().Verify(msg, sig) {
		t.Error("Verify accepts the signature under another key")
	}
	if pub.Verify(append([]byte("x"), msg...), sig) || pub.Verify(msg[:len(msg)-1], sig) || pub.Verify(nil, sig) {
		t.Error("Verify accepts the signature for another message")
	}
	for _, n := range []int{0, 1, 65, 66, 131} {
		if pub.Verify(msg, sig[:n]) {
			t.Errorf("Verify accepts a signature truncated to %d octets", n)
		}
	}
	if pub.Verify(msg, nil) {
		t.Error("Verify accepts a nil signature")
	}
	if pub.Verify(msg, append(append([]byte(nil), sig...), 0)) {
		t.Error("Verify accepts a signature of 133 octets")
	}
	// The signature of the empty message is not the signature of another one.
	empty, err := priv.Sign(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(nil, empty) || pub.Verify([]byte{0}, empty) {
		t.Error("the empty message is not told apart from the one byte message")
	}
}
