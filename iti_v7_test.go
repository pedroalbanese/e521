// SPDX-License-Identifier: ISC

package e521

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
)

// The root certificate "Autoridade Certificadora Raiz Brasileira v7" of
// ICP-Brasil (ITI) is public and signs itself with Ed521. It was downloaded
// from http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv7.crt (PEM,
// converted to DER) and is kept in testdata unchanged.
//
// LCRacraizv7.crl is ITI's CRL for v7 (CRL number 36, last update 2026-10-01),
// from http://acraiz.icpbrasil.gov.br/LCRacraizv7.crl: a second real signature
// by the same key over different bytes.
const itiV7SHA256 = "5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576"

type itiCertificate struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

type itiTBSCertificate struct {
	Version   int `asn1:"optional,explicit,default:0,tag:0"`
	Serial    *big.Int
	Algorithm pkix.AlgorithmIdentifier
	Issuer    asn1.RawValue
	Validity  asn1.RawValue
	Subject   asn1.RawValue
	PublicKey struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
}

type itiCRL struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

func readITI(t *testing.T, name string) []byte {
	t.Helper()
	der, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// itiV7 returns the certificate, the exact bytes the root signed (the DER of
// its TBSCertificate) and the root's public key.
func itiV7(t *testing.T) (cert itiCertificate, key *PublicKey) {
	t.Helper()
	der := readITI(t, "ICP-Brasilv7.der")
	if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) != itiV7SHA256 {
		t.Fatalf("testdata/ICP-Brasilv7.der has SHA-256 %x, want %s", sum, itiV7SHA256)
	}
	if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 {
		t.Fatalf("certificate DER: %v (%d bytes left)", err, len(rest))
	}
	var tbs itiTBSCertificate
	if _, err := asn1.Unmarshal(cert.TBS.FullBytes, &tbs); err != nil {
		t.Fatalf("TBSCertificate DER: %v", err)
	}
	if !cert.Algorithm.Algorithm.Equal(oidE521EdDSA) || !tbs.Algorithm.Algorithm.Equal(oidE521EdDSA) ||
		!tbs.PublicKey.Algorithm.Algorithm.Equal(oidE521EdDSA) {
		t.Fatalf("the OID of v7 is not 1.3.6.1.4.1.44588.2.1: %v %v %v",
			cert.Algorithm.Algorithm, tbs.Algorithm.Algorithm, tbs.PublicKey.Algorithm.Algorithm)
	}
	if !bytes.Equal(tbs.Issuer.FullBytes, tbs.Subject.FullBytes) {
		t.Fatal("v7 is a root: its issuer must equal its subject")
	}
	x, y := E521().DecompressPoint(tbs.PublicKey.Key.Bytes)
	if x == nil || y == nil {
		t.Fatal("the public key of v7 does not decompress")
	}
	return cert, NewPublicKey(x, y)
}

func TestITIv7SelfSignature(t *testing.T) {
	cert, key := itiV7(t)
	tbs, sig := cert.TBS.FullBytes, cert.Signature.Bytes
	if len(sig) != 132 {
		t.Fatalf("signature of v7 has %d octets, want 132", len(sig))
	}
	if !key.Verify(tbs, sig) {
		t.Fatal("the self-signature of the ITI v7 root does not verify")
	}
	if !key.Verify(tbs, sig) {
		t.Error("a second Verify of the same signature failed")
	}
}

func TestITIv7SelfSignatureNegative(t *testing.T) {
	cert, key := itiV7(t)
	tbs, sig := cert.TBS.FullBytes, cert.Signature.Bytes

	for _, i := range []int{0, 7, len(tbs) / 2, len(tbs) - 1} {
		bad := append([]byte(nil), tbs...)
		bad[i] ^= 0x01
		if key.Verify(bad, sig) {
			t.Errorf("v7 verifies a TBSCertificate with byte %d altered", i)
		}
	}
	for _, i := range []int{0, 65, 66, 131} {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 0x01
		if key.Verify(tbs, bad) {
			t.Errorf("v7 verifies a signature with byte %d altered", i)
		}
	}
	if key.Verify(tbs, sig[:131]) || key.Verify(tbs, append(append([]byte(nil), sig...), 0)) {
		t.Error("v7 verifies a signature of 131 or 133 octets")
	}
	if testKey(t).Verify(tbs, sig) {
		t.Error("the self-signature of v7 verifies under another key")
	}
}

func TestITIv7CRLSignature(t *testing.T) {
	_, key := itiV7(t)
	var crl itiCRL
	if rest, err := asn1.Unmarshal(readITI(t, "LCRacraizv7.crl"), &crl); err != nil || len(rest) != 0 {
		t.Fatalf("CRL DER: %v (%d bytes left)", err, len(rest))
	}
	if !crl.Algorithm.Algorithm.Equal(oidE521EdDSA) {
		t.Fatalf("the CRL is signed with %v, want 1.3.6.1.4.1.44588.2.1", crl.Algorithm.Algorithm)
	}
	if !key.Verify(crl.TBS.FullBytes, crl.Signature.Bytes) {
		t.Fatal("the signature of ITI's v7 CRL does not verify under the v7 key")
	}
	bad := append([]byte(nil), crl.TBS.FullBytes...)
	bad[len(bad)/2] ^= 0x01
	if key.Verify(bad, crl.Signature.Bytes) {
		t.Error("v7 verifies a CRL with a byte altered")
	}
}

// TestParsePublicKeyITIv7 parses the SubjectPublicKeyInfo of the real ITI v7
// root. Its AlgorithmIdentifier carries the OID alone, with no parameters.
func TestParsePublicKeyITIv7(t *testing.T) {
	cert, want := itiV7(t)
	var tbs struct {
		Version   int `asn1:"optional,explicit,default:0,tag:0"`
		Serial    *big.Int
		Algorithm pkix.AlgorithmIdentifier
		Issuer    asn1.RawValue
		Validity  asn1.RawValue
		Subject   asn1.RawValue
		PublicKey asn1.RawValue
	}
	if _, err := asn1.Unmarshal(cert.TBS.FullBytes, &tbs); err != nil {
		t.Fatalf("TBSCertificate DER: %v", err)
	}
	got, err := ParsePublicKey(tbs.PublicKey.FullBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey of the ITI v7 root's SubjectPublicKeyInfo: %v", err)
	}
	if got.X.Cmp(want.X) != 0 || got.Y.Cmp(want.Y) != 0 {
		t.Fatal("ParsePublicKey returned another point than the root's key")
	}
	tbsBytes, sig := cert.TBS.FullBytes, cert.Signature.Bytes
	if !got.Verify(tbsBytes, sig) {
		t.Fatal("the parsed key does not verify the root's self-signature")
	}
}

// TestMarshalPublicKeyUnchanged keeps the encoder's output as it was: the
// AlgorithmIdentifier still carries its parameters field, and it parses back.
func TestMarshalPublicKeyUnchanged(t *testing.T) {
	_, key := itiV7(t)
	der, err := key.MarshalPKCS8PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		t.Fatalf("the encoder's output no longer has a parameters field: %v", err)
	}
	back, err := ParsePublicKey(der)
	if err != nil || back.X.Cmp(key.X) != 0 || back.Y.Cmp(key.Y) != 0 {
		t.Fatalf("round trip failed: %v", err)
	}
}
