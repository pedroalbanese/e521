// SPDX-License-Identifier: ISC

package e521

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/sha3"
)

// The vectors in testdata/ed521-pure.json and testdata/ed521-ph.json were made
// by testdata/oracle.py (run by testdata/make_vectors.py): an implementation in
// another language, written from RFC 8032 section 5.2 and ITI DOC-ICP-01.01
// section 2, that shares no code with this package. The keys are public test
// seeds, never anyone's key. Nothing in these files was produced by this
// package.

type vectorFile struct {
	Vectors []struct {
		Name      string `json:"name"`
		Prehash   string `json:"prehash"`
		Public    string `json:"public"`
		Context   string `json:"context"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"vectors"`
}

func readVectors(t *testing.T, name string) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal(name + " has no vectors")
	}
	return f
}

func keyFromHex(t *testing.T, s string) *PublicKey {
	t.Helper()
	x, y := E521().DecompressPoint(mustHex(t, s))
	if x == nil || y == nil {
		t.Fatal("the public key does not decompress: " + s)
	}
	return NewPublicKey(x, y)
}

// PureEd521: phflag 0, empty context, the message signed as it is.
func TestPureEd521IndependentVectors(t *testing.T) {
	for _, v := range readVectors(t, "ed521-pure.json").Vectors {
		pub := keyFromHex(t, v.Public)
		msg, sig := mustHex(t, v.Message), mustHex(t, v.Signature)
		if !pub.Verify(msg, sig) {
			t.Errorf("%s: Verify rejects the oracle's signature", v.Name)
		}
		if len(msg) > 0 {
			bad := append([]byte(nil), msg...)
			bad[0] ^= 1
			if pub.Verify(bad, sig) {
				t.Errorf("%s: Verify accepts another message", v.Name)
			}
		}
	}
}

// verifyDomain is the check of Verify with the domain of dom5 given by the
// caller. The package has no Ed521ph function yet, so the test builds one
// from the package's own hashE521 and curve operations: it is what the
// vectors below test, together with dom5.
func verifyDomain(pub *PublicKey, signed, sig []byte, phflag byte, context []byte) bool {
	curve := pub.Curve
	byteLen := (curve.BitSize + 7) / 8
	if len(sig) != 2*byteLen {
		return false
	}
	Rx, Ry := curve.DecompressPoint(sig[:byteLen])
	if Rx == nil || Ry == nil {
		return false
	}
	s := bytesToLittleInt(sig[byteLen:])
	if s.Cmp(curve.N) >= 0 {
		return false
	}
	input := append(append(append([]byte(nil), sig[:byteLen]...), curve.CompressPoint(pub.X, pub.Y)...), signed...)
	k := bytesToLittleInt(hashE521(phflag, context, input))
	k.Mod(k, curve.N)
	sGx, sGy := curve.ScalarBaseMult(littleIntToBytes(s, byteLen))
	kAx, kAy := curve.ScalarMult(pub.X, pub.Y, littleIntToBytes(k, byteLen))
	rx, ry := curve.Add(Rx, Ry, kAx, kAy)
	return constantTimeEqual(sGx, rx) && constantTimeEqual(sGy, ry)
}

// Ed521ph (DOC-ICP-01.01 2.2): phflag 1, and PH is SHA-3 (512 bits) or
// SHAKE256(x, 64); dom5 carries a context of up to 255 octets (2.3).
func TestEd521phIndependentVectors(t *testing.T) {
	prehash := map[string]func([]byte) []byte{
		"SHAKE256-64": func(m []byte) []byte {
			out := make([]byte, 64)
			sha3.ShakeSum256(out, m)
			return out
		},
		"SHA3-512": func(m []byte) []byte { s := sha3.Sum512(m); return s[:] },
	}
	for _, v := range readVectors(t, "ed521-ph.json").Vectors {
		ph, ok := prehash[v.Prehash]
		if !ok {
			t.Fatalf("%s: unknown prehash %q", v.Name, v.Prehash)
		}
		pub := keyFromHex(t, v.Public)
		msg, sig, ctx := mustHex(t, v.Message), mustHex(t, v.Signature), mustHex(t, v.Context)
		signed := ph(msg)
		if !verifyDomain(pub, signed, sig, 1, ctx) {
			t.Errorf("%s: the oracle's Ed521ph signature is rejected", v.Name)
		}
		if verifyDomain(pub, signed, sig, 0, ctx) {
			t.Errorf("%s: accepted with phflag 0", v.Name)
		}
		other := append([]byte(nil), ctx...)
		if len(other) == 0 {
			other = []byte{'x'}
		} else {
			other[0] ^= 1
		}
		if verifyDomain(pub, signed, sig, 1, other) {
			t.Errorf("%s: accepted with another context", v.Name)
		}
		if verifyDomain(pub, msg, sig, 1, ctx) {
			t.Errorf("%s: accepted over the message instead of PH(message)", v.Name)
		}
		// An Ed521ph signature is not a PureEd521 one, whatever is signed.
		if pub.Verify(signed, sig) || pub.Verify(msg, sig) {
			t.Errorf("%s: Verify (PureEd521) accepts an Ed521ph signature", v.Name)
		}
	}
}

// dom5(x, y) = "SigEd521" || octet(x) || octet(OLEN(y)) || y (DOC-ICP-01.01 2.3).
func TestDom5(t *testing.T) {
	for _, c := range []struct {
		phflag  byte
		context []byte
		want    string
	}{
		{0, nil, "536967456435323100" + "00"},
		{1, nil, "536967456435323101" + "00"},
		{0, []byte("foo"), "536967456435323100" + "03" + "666f6f"},
		{1, bytes.Repeat([]byte{0xab}, 255), "536967456435323101" + "ff" + hex.EncodeToString(bytes.Repeat([]byte{0xab}, 255))},
	} {
		if got := hex.EncodeToString(dom5(c.phflag, c.context)); got != c.want {
			t.Errorf("dom5(%d, %x) = %s, want %s", c.phflag, c.context, got, c.want)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("dom5 accepts a context of 256 octets")
		}
	}()
	dom5(0, make([]byte, 256))
}
