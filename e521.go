// SPDX-License-Identifier: ISC
//
// Copyright (c) 2025 Pedro F. Albanese
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// ---------------------------------------------------------------------------
//
// Implements support for ECC over Curve E-521 as specified in the
// Brazilian national cryptographic standards defined in:
//
//   ITI DOC-ICP-01.01 — Brazilian Cryptographic Standards for Public-Key Algorithms
//
// This standard is maintained under the ICP-Brasil framework by the
// Instituto Nacional de Tecnologia da Informação (ITI) and mandates the
// use of secure, internationally reviewed algorithms for digital
// certificates and electronic signatures.
//
// Curve E-521 is a high-security elliptic curve consistent with 512-bit
// security strength and is considered future-safe for use in digital
// signatures and key agreement protocols.
//
// Officially approved via:
//   - Instrução Normativa ITI nº 22, de 23 de março de 2022
//
// References:
//   - ICP-Brasil – DOC-ICP-01.01, v5.0 (2022) 
//     https://www.gov.br/iti/pt-br/assuntos/legislacao/documentos-principais/IN2022_22_DOC_ICP_01.01_assinado.pdf
//   - Instrução Normativa ITI nº 22/2022 – Instituto Nacional de Tecnologia da Informação
//   - Diego F. Aranha, Paulo S. L. M. Barreto, Geovandro C. C. F. Pereira, Jefferson Ricardini,
//     "A note on high-security general-purpose elliptic curves", 2013.
//     https://eprint.iacr.org/2013/647
//
// This code implements PureEdDSA using SHAKE256 over the E-521 Edwards curve,
// compliant with the above specifications.
package e521

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"sync"
	
	"golang.org/x/crypto/sha3"
)

var (
	// OID oficial definido pelo ITI (ICP-Brasil) para identificação da curva E-521 EdDSA
    // Conforme DOC-ICP-01.01
	oidE521EdDSA = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44588, 2, 1}
)

var initonce sync.Once
var e521Curve *Curve

// Parâmetros da curva E-521 (Edwards)
var (
	// p = 2^521 - 1
	e521P, _ = new(big.Int).SetString("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	
	// Ordem do grupo
	e521N, _ = new(big.Int).SetString("7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b", 16)
	
	// Coeficiente d da curva de Edwards
	e521D, _ = new(big.Int).SetString("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa4331", 16)
	
	// Ponto gerador
	e521Gx, _ = new(big.Int).SetString("752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c", 16)
	e521Gy    = big.NewInt(0x0c)
	
	// Co-factor
	e521H = big.NewInt(4)
)

// Curve representa uma curva elíptica
type Curve struct {
	Name    string
	P       *big.Int // Ordem do campo primo
	N       *big.Int // Ordem do grupo
	D       *big.Int // Parâmetro d da curva de Edwards
	Gx, Gy  *big.Int // Ponto gerador
	BitSize int      // Tamanho do campo em bits
}

// Point representa um ponto na curva
type Point struct {
	X, Y *big.Int
}

// PublicKey representa uma chave pública E-521 EdDSA
type PublicKey struct {
	Point
	Curve *Curve
}

// PrivateKey representa uma chave privada E-521 EdDSA
type PrivateKey struct {
	PublicKey
	D *big.Int // Escalar privado (a)
}

// pkAlgorithmIdentifier para ASN.1
type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

func initE521() {
	e521Curve = &Curve{
		Name:    "E-521",
		P:       new(big.Int).Set(e521P),
		N:       new(big.Int).Set(e521N),
		D:       new(big.Int).Set(e521D),
		Gx:      new(big.Int).Set(e521Gx),
		Gy:      new(big.Int).Set(e521Gy),
		BitSize: 521,
	}
}

// E521 retorna a curva E-521
func E521() *Curve {
	initonce.Do(initE521)
	return e521Curve
}

// IsOnCurve verifica se um ponto está na curva
func (curve *Curve) IsOnCurve(x, y *big.Int) bool {
	// Verifica a equação de Edwards: x² + y² ≡ 1 + d*x²*y² (mod p)
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, curve.P)
	
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)
	
	left := new(big.Int).Add(x2, y2)
	left.Mod(left, curve.P)
	
	dx2y2 := new(big.Int).Mul(x2, y2)
	dx2y2.Mul(dx2y2, curve.D)
	dx2y2.Mod(dx2y2, curve.P)
	
	right := new(big.Int).Add(big.NewInt(1), dx2y2)
	right.Mod(right, curve.P)
	
	return left.Cmp(right) == 0
}

// Add adiciona dois pontos na curva Edwards
func (curve *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return x2, y2
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return x1, y1
	}
	
	// Fórmulas de adição para curvas de Edwards
	// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
	// y3 = (y1*y2 - x1*x2) / (1 - d*x1*x2*y1*y2)
	
	x1y2 := new(big.Int).Mul(x1, y2)
	y1x2 := new(big.Int).Mul(y1, x2)
	numeratorX := new(big.Int).Add(x1y2, y1x2)
	
	y1y2 := new(big.Int).Mul(y1, y2)
	x1x2 := new(big.Int).Mul(x1, x2)
	numeratorY := new(big.Int).Sub(y1y2, x1x2)
	
	dx1x2y1y2 := new(big.Int).Mul(x1x2, y1y2)
	dx1x2y1y2.Mul(dx1x2y1y2, curve.D)
	dx1x2y1y2.Mod(dx1x2y1y2, curve.P)
	
	denominatorX := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
	denominatorY := new(big.Int).Sub(big.NewInt(1), dx1x2y1y2)
	
	// Encontrar inversos modulares
	invDenomX := new(big.Int).ModInverse(denominatorX, curve.P)
	invDenomY := new(big.Int).ModInverse(denominatorY, curve.P)
	
	x3 := new(big.Int).Mul(numeratorX, invDenomX)
	x3.Mod(x3, curve.P)
	
	y3 := new(big.Int).Mul(numeratorY, invDenomY)
	y3.Mod(y3, curve.P)
	
	return x3, y3
}

// Double dobra um ponto na curva Edwards
func (curve *Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return curve.Add(x1, y1, x1, y1)
}

// ScalarMult multiplica um ponto por um escalar
func (curve *Curve) ScalarMult(x, y *big.Int, k []byte) (*big.Int, *big.Int) {
	// k deve estar em little-endian conforme RFC 8032
	scalar := bytesToLittleInt(k)
	scalar.Mod(scalar, curve.N)
	
	resultX := big.NewInt(0)
	resultY := big.NewInt(1) // Ponto neutro em Edwards: (0, 1)
	
	tempX := new(big.Int).Set(x)
	tempY := new(big.Int).Set(y)
	
	for scalar.BitLen() > 0 {
		if scalar.Bit(0) == 1 {
			resultX, resultY = curve.Add(resultX, resultY, tempX, tempY)
		}
		tempX, tempY = curve.Double(tempX, tempY)
		scalar.Rsh(scalar, 1)
	}
	
	return resultX, resultY
}

// ScalarBaseMult multiplica o ponto gerador por um escalar
func (curve *Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

// Params retorna os parâmetros da curva
func (curve *Curve) Params() *Curve {
	return curve
}

// GenerateKey gera um par de chaves E-521 EdDSA
func GenerateKey() (*PrivateKey, error) {
	return GenerateKeyWithReader(rand.Reader)
}

// GenerateKeyWithReader gera um par de chaves E-521 EdDSA com um leitor específico
func GenerateKeyWithReader(reader io.Reader) (*PrivateKey, error) {
	curve := E521()
	
	// Gerar chave privada aleatória (escalar a) em little-endian
	privateKey, err := randLittleInt(reader, curve.N)
	if err != nil {
		return nil, err
	}
	
	// Calcular chave pública: A = a * G
	publicKeyX, publicKeyY := curve.ScalarBaseMult(littleIntToBytes(privateKey, (curve.BitSize+7)/8))
	
	return &PrivateKey{
		PublicKey: PublicKey{
			Point: Point{
				X: publicKeyX,
				Y: publicKeyY,
			},
			Curve: curve,
		},
		D: privateKey,
	}, nil
}

// randLittleInt gera um número aleatório em little-endian usando o reader fornecido
func randLittleInt(reader io.Reader, max *big.Int) (*big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	
	// Calcular o número de bytes necessário
	byteLen := (max.BitLen() + 7) / 8
	buf := make([]byte, byteLen)
	
	for {
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			return nil, err
		}
		
		// Garantir que o número é menor que max (em little-endian)
		num := bytesToLittleInt(buf)
		if num.Cmp(max) < 0 {
			return num, nil
		}
	}
}

// Marshal serializa um ponto no formato não comprimido (big-endian para compatibilidade)
func (curve *Curve) Marshal(x, y *big.Int) []byte {
	byteLen := (curve.BitSize + 7) / 8
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // ponto não comprimido
	
	xBytes := littleIntToBytes(x, byteLen)
	yBytes := littleIntToBytes(y, byteLen)
	
	copy(ret[1:1+byteLen], xBytes)
	copy(ret[1+byteLen:], yBytes)
	
	return ret
}

// Unmarshal desserializa um ponto do formato não comprimido (big-endian para compatibilidade)
func (curve *Curve) Unmarshal(data []byte) (*big.Int, *big.Int) {
	if len(data) == 0 {
		return nil, nil
	}
	
	byteLen := (curve.BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	
	if data[0] != 4 { // apenas suporte a formato não comprimido
		return nil, nil
	}
	
	x := bytesToLittleInt(data[1 : 1+byteLen])
	y := bytesToLittleInt(data[1+byteLen:])
	
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	
	return x, y
}

// MarshalPKCS8PublicKey serializa uma chave pública no formato PKCS#8 com chave comprimida
func (pub *PublicKey) MarshalPKCS8PublicKey() ([]byte, error) {
	if pub.Curve != E521() {
		return nil, errors.New("unsupported curve")
	}
	
	// Comprimir o ponto público conforme RFC 8032
	compressedPubKey := pub.Curve.CompressPoint(pub.X, pub.Y)
	
	// Criar estrutura SubjectPublicKeyInfo
	subjectPublicKeyInfo := struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  oidE521EdDSA,
			Parameters: asn1.RawValue{Tag: asn1.TagOID},
		},
		PublicKey: asn1.BitString{Bytes: compressedPubKey, BitLength: len(compressedPubKey) * 8},
	}
	
	// Marshal da estrutura
	return asn1.Marshal(subjectPublicKeyInfo)
}

// ParsePublicKey analisa uma chave pública no formato PKCS#8 com chave comprimida
func ParsePublicKey(der []byte) (*PublicKey, error) {
	var publicKeyInfo struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}
	
	_, err := asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		return nil, err
	}
	
	// Verificar OID
	if !publicKeyInfo.Algorithm.Algorithm.Equal(oidE521EdDSA) {
		return nil, errors.New("unsupported curve OID")
	}
	
	curve := E521()
	
	// Verificar se os bytes da chave pública não estão vazios
	if len(publicKeyInfo.PublicKey.Bytes) == 0 {
		return nil, errors.New("public key bytes are empty")
	}
	
	// Descomprimir o ponto público conforme RFC 8032
	x, y := curve.DecompressPoint(publicKeyInfo.PublicKey.Bytes)
	if x == nil || y == nil {
		return nil, errors.New("failed to decompress public key")
	}
	
	return &PublicKey{
		Point: Point{
			X: x,
			Y: y,
		},
		Curve: curve,
	}, nil
}

// MarshalPKCS8PrivateKey serializa uma chave privada no formato PKCS#8 com chave pública comprimida
func (priv *PrivateKey) MarshalPKCS8PrivateKey() ([]byte, error) {
	if priv.Curve != E521() {
		return nil, errors.New("unsupported curve")
	}
	
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
		return nil, errors.New("public key is not on the curve")
	}
	
	// Converter chave privada D para bytes (little-endian)
	curveSize := (priv.Curve.BitSize + 7) / 8
	dBytes := littleIntToBytes(priv.D, curveSize)
	
	// Comprimir a chave pública conforme RFC 8032
	compressedPubKey := priv.Curve.CompressPoint(priv.X, priv.Y)
	
	// Criar estrutura PrivateKeyInfo
	privateKeyInfo := struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PrivateKey          []byte `asn1:"tag:4"` // OCTET STRING
		PublicKey           asn1.BitString `asn1:"optional,explicit,tag:1"`
	}{
		Version: 0,
		PrivateKeyAlgorithm: pkAlgorithmIdentifier{
			Algorithm:  oidE521EdDSA,
			Parameters: asn1.RawValue{Tag: asn1.TagOID},
		},
		PrivateKey: dBytes,
		PublicKey:  asn1.BitString{Bytes: compressedPubKey, BitLength: len(compressedPubKey) * 8},
	}
	
	// Marshal da estrutura
	return asn1.Marshal(privateKeyInfo)
}

// ParsePrivateKey analisa uma chave privada no formato PKCS#8 com chave pública comprimida
func ParsePrivateKey(der []byte) (*PrivateKey, error) {
	var privateKeyInfo struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PrivateKey          []byte `asn1:"tag:4"`
		PublicKey           asn1.BitString `asn1:"optional,explicit,tag:1"`
	}
	
	_, err := asn1.Unmarshal(der, &privateKeyInfo)
	if err != nil {
		return nil, err
	}
	
	// Verificar OID
	if !privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidE521EdDSA) {
		return nil, errors.New("unsupported curve OID")
	}
	
	curve := E521()
	
	// Extrair chave privada D (little-endian)
	D := bytesToLittleInt(privateKeyInfo.PrivateKey)
	
	// Extrair e descomprimir chave pública se disponível
	var x, y *big.Int
	if len(privateKeyInfo.PublicKey.Bytes) > 0 {
		x, y = curve.DecompressPoint(privateKeyInfo.PublicKey.Bytes)
	} else {
		// Calcular chave pública a partir da chave privada e comprimir
		curveSize := (curve.BitSize + 7) / 8
		x, y = curve.ScalarBaseMult(littleIntToBytes(D, curveSize))
	}
	
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal public key")
	}
	
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("public key is not on the curve")
	}
	
	return &PrivateKey{
		PublicKey: PublicKey{
			Point: Point{
				X: x,
				Y: y,
			},
			Curve: curve,
		},
		D: D,
	}, nil
}

// dom5
func dom5(phflag byte, context []byte) []byte {
    if len(context) > 255 {
        panic("context too long for dom5")
    }

    dom := []byte("SigEd521")
    dom = append(dom, phflag)
    dom = append(dom, byte(len(context)))
    dom = append(dom, context...)
    return dom
}

// hashE521 implementa H(x) = SHAKE256(dom5(phflag,context)||x, 132)
func hashE521(phflag byte, context, x []byte) []byte {
    dom := dom5(phflag, context)
    
    h := sha3.NewShake256()
    h.Write(dom)
    h.Write(x)
    
    // Output de 132 bytes conforme especificação
    hash := make([]byte, 132)
    h.Read(hash)
    return hash
}

// CompressPoint compresses Edwards point according to RFC 8032: store sign bit of x
func (c *Curve) CompressPoint(x, y *big.Int) []byte {
	byteLen := (c.BitSize + 7) / 8
	yBytes := littleIntToBytes(y, byteLen)

	// Get the sign bit from x (LSB in little-endian representation)
	xBytes := littleIntToBytes(x, byteLen)
	signBit := xBytes[0] & 1

	// Store sign bit in the LSB of the last byte of yBytes (RFC 8032)
	compressed := make([]byte, byteLen)
	copy(compressed, yBytes)
	compressed[byteLen-1] |= signBit << 7 // MSB do último byte em little-endian

	return compressed
}

// DecompressPoint decompresses a compressed point according to RFC 8032
func (c *Curve) DecompressPoint(data []byte) (*big.Int, *big.Int) {
	byteLen := (c.BitSize + 7) / 8
	if len(data) != byteLen {
		return nil, nil
	}

	// Extract sign bit from MSB of last byte
	signBit := (data[byteLen-1] >> 7) & 1

	// Clear the sign bit from y data
	yBytes := make([]byte, byteLen)
	copy(yBytes, data)
	yBytes[byteLen-1] &= 0x7F // Clear MSB

	y := bytesToLittleInt(yBytes)

	// Solve for x using Edwards curve equation: x² + y² = 1 + d*x²*y²
	// Rearranged to: x² = (1 - y²) / (1 - d*y²)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, c.P)

	// numerator = 1 - y²
	numerator := new(big.Int).Sub(big.NewInt(1), y2)
	numerator.Mod(numerator, c.P)

	// denominator = 1 - d*y²
	dy2 := new(big.Int).Mul(y2, c.D)
	dy2.Mod(dy2, c.P)
	denominator := new(big.Int).Sub(big.NewInt(1), dy2)
	denominator.Mod(denominator, c.P)

	// x² = numerator / denominator
	invDenom := new(big.Int).ModInverse(denominator, c.P)
	if invDenom == nil {
		return nil, nil
	}

	x2 := new(big.Int).Mul(numerator, invDenom)
	x2.Mod(x2, c.P)

	// Calculate square root
	x := new(big.Int).ModSqrt(x2, c.P)
	if x == nil {
		return nil, nil
	}

	// Choose correct x based on sign bit (RFC 8032 uses sign of x)
	xBytes := littleIntToBytes(x, byteLen)
	if (xBytes[0] & 1) != signBit {
		x.Sub(c.P, x)
		x.Mod(x, c.P)
	}

	return x, y
}

// Sign creates a signature for message, returning 1+ curveSize+ scalar size bytes
func (priv *PrivateKey) Sign(message []byte) ([]byte, error) {
	curve := priv.Curve
	byteLen := (curve.BitSize + 7) / 8

	// 1. Hash prefix "dom" + priv.D bytes
	prefix := hashE521(0x00, []byte{}, littleIntToBytes(priv.D, byteLen))

	// 2. Calculate r = SHAKE256(prefix || message) mod N
	rBytes := hashE521(0x00, []byte{}, append(prefix, message...))
	r := bytesToLittleInt(rBytes[:byteLen])
	r.Mod(r, curve.N)

	// 3. Compute R = r*G and compress
	Rx, Ry := curve.ScalarBaseMult(littleIntToBytes(r, byteLen))
	RCompressed := curve.CompressPoint(Rx, Ry)

	// 4. Compress public key A
	ACompressed := curve.CompressPoint(priv.X, priv.Y)

	// 5. Compute h = SHAKE256(dom || R || A || message) mod N
	hramInput := append(append(RCompressed, ACompressed...), message...)
	hramHash := hashE521(0x00, []byte{}, hramInput)
	hram := bytesToLittleInt(hramHash[:byteLen])
	hram.Mod(hram, curve.N)

	// 6. s = (r + h * a) mod N
	s := new(big.Int).Mul(hram, priv.D)
	s.Add(s, r)
	s.Mod(s, curve.N)

	// 7. Signature = RCompressed || sBytes
	sBytes := littleIntToBytes(s, byteLen)
	signature := append(RCompressed, sBytes...)

	return signature, nil
}

// Verify verifies the signature of message for a given public key
func (pub *PublicKey) Verify(message, sig []byte) bool {
	curve := pub.Curve
	byteLen := (curve.BitSize + 7) / 8

	if len(sig) != byteLen*2 {
		return false
	}

	RCompressed := sig[:byteLen]
	sBytes := sig[byteLen:]

	Rx, Ry := curve.DecompressPoint(RCompressed)
	if Rx == nil || Ry == nil {
		return false
	}

	s := bytesToLittleInt(sBytes)
	if s.Cmp(curve.N) >= 0 {
		return false
	}

	ACompressed := curve.CompressPoint(pub.X, pub.Y)

	// Compute h = SHAKE256(dom || R || A || message) mod N
	hramInput := append(append(RCompressed, ACompressed...), message...)
	hramHash := hashE521(0x00, []byte{}, hramInput)
	hram := bytesToLittleInt(hramHash[:byteLen])
	hram.Mod(hram, curve.N)

	// Compute s*G
	sGx, sGy := curve.ScalarBaseMult(littleIntToBytes(s, byteLen))

	// Compute h*A
	hAx, hAy := curve.ScalarMult(pub.X, pub.Y, littleIntToBytes(hram, byteLen))

	// Compute R + h*A
	rhaX, rhaY := curve.Add(Rx, Ry, hAx, hAy)

	// Constant time comparison
	return constantTimeEqual(sGx, rhaX) && constantTimeEqual(sGy, rhaY)
}

// bytesToLittleInt converte bytes little-endian para big.Int
func bytesToLittleInt(b []byte) *big.Int {
	// Reverter para big-endian para big.Int
	reversed := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		reversed[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(reversed)
}

// littleIntToBytes converte big.Int para bytes little-endian
func littleIntToBytes(n *big.Int, length int) []byte {
	bytes := n.Bytes()
	
	// Padding se necessário
	if len(bytes) < length {
		padding := make([]byte, length-len(bytes))
		bytes = append(padding, bytes...)
	}
	
	// Reverter para little-endian
	reversed := make([]byte, length)
	for i := 0; i < length; i++ {
		reversed[i] = bytes[length-1-i]
	}
	
	return reversed
}

// constantTimeEqual compara dois big.Int em tempo constante
func constantTimeEqual(a, b *big.Int) bool {
	if a == nil || b == nil {
		return false
	}
	
	aBytes := a.Bytes()
	bBytes := b.Bytes()
	
	// Garantir que ambos tenham o mesmo tamanho
	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}
	
	aPadded := make([]byte, maxLen)
	bPadded := make([]byte, maxLen)
	
	copy(aPadded[maxLen-len(aBytes):], aBytes)
	copy(bPadded[maxLen-len(bBytes):], bBytes)
	
	// Usar subtle.ConstantTimeCompare para comparação em tempo constante
	return subtle.ConstantTimeCompare(aPadded, bPadded) == 1
}

// GetPublic retorna a chave pública associada
func (priv *PrivateKey) GetPublic() *PublicKey {
	return &priv.PublicKey
}

// Equal compara duas chaves públicas
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if pub.Curve != other.Curve {
		return false
	}
	return pub.X.Cmp(other.X) == 0 && pub.Y.Cmp(other.Y) == 0
}

// NewPublicKey cria uma nova chave pública a partir de coordenadas
func NewPublicKey(x, y *big.Int) *PublicKey {
	curve := E521()
	return &PublicKey{
		Point: Point{X: x, Y: y},
		Curve: curve,
	}
}
