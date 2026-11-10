// SPDX-License-Identifier: ISC

package e521

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

// The vectors below were made by testdata/oracle.py, an independent
// implementation written from RFC 8032 section 5.2 and from ITI DOC-ICP-01.01
// section 2 (H(x) = SHAKE256(dom5(phflag,context)||x, 132)). It shares no code
// with this package. The key is a public test seed, never for real use:
//
//	seed = SHAKE256("Sparky CA Ed521 TEST key 0: public seed, never for real use", 66)
//
//	cd testdata && python3 -c "
//	import hashlib, oracle
//	C = oracle.ED521
//	seed = hashlib.shake_256(b'Sparky CA Ed521 TEST key 0: public seed, never for real use').digest(66)
//	print(C.public_key(seed).hex())
//	print(C.sign(seed, b'abc').hex())"
const (
	testPublicKey = "b18f0469893c33dfd716f5f1260787447181107032e1e50a668c04b9c189f9cf7265719dfe9a5a47b8250ec56df0389fd5e2ea68444236f2b15bd77c8745fa45b600"

	// The scalar of the public test seed after the RFC 8032 section 5.2.5
	// expansion, big-endian; PrivateKey.D holds exactly this value.
	testScalar = "182a57fee97fe18c401028775ea64efb05dfb85d5b2017849471e3f1da33038012fb5fa1a04ae215c4b8348e9a4405124c9852f86bc7935a519a9b5004e247f96a0"

	testSignatureEmpty = "ba65be4ba3f8708c2838de24eaa683bd02ae0c1b469190e9c28aed6b7c662228d8bf981b5ad19513a1989277c5d94265943bb6abd2f5667fc362945f6cc41fb25d81baeca74db5d49ee75a33f711419331eae013f4c84fe63f2c5d1b3c24639b6685f84fd2a08b7e5a064e77d93b235d29f679c0a8d33619e33c6a642e6f09b664322000"
	testSignatureABC   = "13ce0b331a7c0da181e3bbc15441036443b131b1218746540353ef3587490991513883fb510e73d0040a3de9213d9fb72dbfcc15c2b3a72983a4568f8c665494c201c4d217ed95562eebd83e422bbe6d80cca45a6a629577550b679bea4c9ef27c62024647e586df2c77b43a85d83a7a21925915d0907ffd3b5bcb39ccd22cfc73061900"

	// A signature made by this package's Sign with testScalar over "abc".
	// The independent oracle verifies it (oracle.ED521.verify, same public
	// key), so Sign is checked by the second implementation, not by Verify.
	// The prefix of Sign is this package's own (H(a)), so it differs from
	// the oracle's signature above; both verify.
	testSignatureSignABC = "d02ef93a1fca0956885694f147fa408977eaa3f75c02f4901cb17aff12d9b41c55d18ecdd53dd47abb8a2f0f35f99244f89fe60a1a14a522f28134093c1f0983fc8023ec7c402d7f85bd1ceee9c73227a32060f9c1720805abb7174ab0a4ca38856d412c79d20c65d4cec9f91d8c3059f2025977ae98c1bee7fe19fa0ee275b554551e00"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testKey(t *testing.T) *PublicKey {
	t.Helper()
	curve := E521()
	x, y := curve.DecompressPoint(mustHex(t, testPublicKey))
	if x == nil || y == nil {
		t.Fatal("the public test key does not decompress")
	}
	return NewPublicKey(x, y)
}

// H(x) uses all 132 octets of SHAKE256 (DOC-ICP-01.01 section 2: H(x) =
// SHAKE256(dom5(phflag,context)||x, 132)); r and the challenge are those 132
// octets as one little-endian integer reduced modulo L, not their first 66.
func TestVerifyIndependentSignatures(t *testing.T) {
	pub := testKey(t)
	for name, c := range map[string]struct{ msg, sig string }{
		"empty": {"", testSignatureEmpty},
		"abc":   {"616263", testSignatureABC},
	} {
		if !pub.Verify(mustHex(t, c.msg), mustHex(t, c.sig)) {
			t.Errorf("%s: a valid signature from the independent oracle was rejected", name)
		}
	}
}

func TestSignVerifiedByIndependentOracle(t *testing.T) {
	d, ok := new(big.Int).SetString(testScalar, 16)
	if !ok {
		t.Fatal("bad test scalar")
	}
	priv := &PrivateKey{D: d, curve: E521()}
	pub := priv.GetPublic()
	if got := hex.EncodeToString(pub.Curve.CompressPoint(pub.X, pub.Y)); got != testPublicKey {
		t.Fatalf("public key of the test scalar = %s, want %s", got, testPublicKey)
	}
	sig, err := priv.Sign([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, testSignatureSignABC); !bytes.Equal(sig, want) {
		t.Errorf("Sign = %x\nwant   %x", sig, want)
	}
	if !pub.Verify([]byte("abc"), sig) {
		t.Error("Verify rejects the signature Sign made")
	}
}
