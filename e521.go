package e521

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"sync"
)

var (
	// OID para identificação da curva E-521 EdDSA
	oidE521EdDSA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 8}
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

// ECDSASignature representa uma assinatura ECDSA no formato ASN.1
type ECDSASignature struct {
	R, S *big.Int
}

// EdDSASignature representa uma assinatura EdDSA
type EdDSASignature struct {
	R *Point
	S *big.Int
}

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

// PublicKey representa uma chave pública E-521
type PublicKey struct {
	Point
	Curve *Curve
}

// PrivateKey representa uma chave privada E-521
type PrivateKey struct {
	PublicKey
	D     *big.Int    // Escalar privado
	Seed  []byte      // Seed original (64 bytes para Ed521)
}

// pkAlgorithmIdentifier para ASN.1
type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

func initE521() {
	e521Curve = &Curve{
		Name:    "E-521 EdDSA",
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
	scalar := new(big.Int).SetBytes(k)
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
	// Gerar seed aleatória (64 bytes para Ed521)
	seed := make([]byte, 64)
	if reader == nil {
		reader = rand.Reader
	}
	_, err := io.ReadFull(reader, seed)
	if err != nil {
		return nil, err
	}
	
	return DerivePrivateKey(seed)
}

// DerivePrivateKey deriva uma chave privada EdDSA a partir de uma seed
func DerivePrivateKey(seed []byte) (*PrivateKey, error) {
	curve := E521()
	
	// Hash da seed usando SHA-512
	hash := sha512.Sum512(seed)
	
	// Primeiros 32 bytes: chave privada escalar (com bits ajustados)
	privateScalar := make([]byte, 66) // 528 bits para E-521
	copy(privateScalar, hash[:32])
	
	// Ajustes específicos do EdDSA
	privateScalar[0] &= 248  // Limpar bits baixos
	privateScalar[31] &= 127 // Limpar bit alto
	privateScalar[31] |= 64  // Setar bit alto
	
	// Converter para big.Int
	scalarInt := new(big.Int).SetBytes(privateScalar)
	scalarInt.Mod(scalarInt, curve.N)
	
	// Calcular chave pública: A = a * G
	publicKeyX, publicKeyY := curve.ScalarBaseMult(scalarInt.Bytes())
	
	return &PrivateKey{
		PublicKey: PublicKey{
			Point: Point{
				X: publicKeyX,
				Y: publicKeyY,
			},
			Curve: curve,
		},
		D:    scalarInt,
		Seed: seed,
	}, nil
}

// randInt gera um número aleatório usando o reader fornecido
func randInt(reader io.Reader, max *big.Int) (*big.Int, error) {
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
		
		// Garantir que o número é menor que max
		num := new(big.Int).SetBytes(buf)
		if num.Cmp(max) < 0 {
			return num, nil
		}
	}
}

// Marshal serializa um ponto no formato não comprimido
func (curve *Curve) Marshal(x, y *big.Int) []byte {
	byteLen := (curve.BitSize + 7) / 8
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // ponto não comprimido
	
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	
	copy(ret[1+byteLen-len(xBytes):1+byteLen], xBytes)
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
	
	return ret
}

// Unmarshal desserializa um ponto do formato não comprimido
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
	
	x := new(big.Int).SetBytes(data[1 : 1+byteLen])
	y := new(big.Int).SetBytes(data[1+byteLen:])
	
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	
	return x, y
}

// MarshalPKCS8PublicKey serializa uma chave pública no formato PKCS#8
func (pub *PublicKey) MarshalPKCS8PublicKey() ([]byte, error) {
	if pub.Curve != E521() {
		return nil, errors.New("unsupported curve")
	}
	
	// Marshal das coordenadas do ponto
	derBytes := pub.Curve.Marshal(pub.X, pub.Y)
	
	// Criar estrutura SubjectPublicKeyInfo
	subjectPublicKeyInfo := struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  oidE521EdDSA,
			Parameters: asn1.RawValue{Tag: asn1.TagOID},
		},
		PublicKey: asn1.BitString{Bytes: derBytes, BitLength: len(derBytes) * 8},
	}
	
	// Marshal da estrutura
	return asn1.Marshal(subjectPublicKeyInfo)
}

// ParsePublicKey analisa uma chave pública no formato PKCS#8
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
	
	// Unmarshal das coordenadas do ponto
	x, y := curve.Unmarshal(publicKeyInfo.PublicKey.Bytes)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal public key")
	}
	
	return &PublicKey{
		Point: Point{
			X: x,
			Y: y,
		},
		Curve: curve,
	}, nil
}

// MarshalPKCS8PrivateKey serializa uma chave privada no formato PKCS#8
func (priv *PrivateKey) MarshalPKCS8PrivateKey() ([]byte, error) {
	if priv.Curve != E521() {
		return nil, errors.New("unsupported curve")
	}
	
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
		return nil, errors.New("public key is not on the curve")
	}
	
	// Converter chave privada D para bytes
	dBytes := priv.D.Bytes()
	curveSize := (priv.Curve.BitSize + 7) / 8
	
	// Padding se necessário
	if len(dBytes) < curveSize {
		padding := make([]byte, curveSize-len(dBytes))
		dBytes = append(padding, dBytes...)
	}
	
	// Marshal da chave pública
	publicKeyBytes := priv.Curve.Marshal(priv.X, priv.Y)
	
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
		PublicKey:  asn1.BitString{Bytes: publicKeyBytes, BitLength: len(publicKeyBytes) * 8},
	}
	
	// Marshal da estrutura
	return asn1.Marshal(privateKeyInfo)
}

// ParsePrivateKey analisa uma chave privada no formato PKCS#8
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
	
	// Extrair chave privada D
	D := new(big.Int).SetBytes(privateKeyInfo.PrivateKey)
	
	// Extrair chave pública se disponível
	var x, y *big.Int
	if len(privateKeyInfo.PublicKey.Bytes) > 0 {
		x, y = curve.Unmarshal(privateKeyInfo.PublicKey.Bytes)
	} else {
		// Calcular chave pública a partir da chave privada
		x, y = curve.ScalarBaseMult(privateKeyInfo.PrivateKey)
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

// ECDH calcula o segredo compartilhado ECDH
func ECDH(privateKey *PrivateKey, publicKey *PublicKey) ([]byte, error) {
	if privateKey.Curve != publicKey.Curve {
		return nil, errors.New("curves do not match")
	}
	
	// Computar segredo compartilhado
	x, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	
	// Retornar coordenada x como segredo
	return x.Bytes(), nil
}

// SignEdDSA assina uma mensagem usando PureEdDSA
func (priv *PrivateKey) SignEdDSA(message []byte) (*EdDSASignature, error) {
	curve := priv.Curve
	
	// Dom: contexto específico do domínio (vazio para PureEdDSA)
	dom := []byte{}
	
	// Calcular r = SHA512(dom(2) || priv[32..64] || message)
	h := sha512.New()
	h.Write(dom)
	h.Write(priv.Seed[32:]) // Segundo half da seed
	h.Write(message)
	rHash := h.Sum(nil)
	
	// Converter r para escalar
	r := new(big.Int).SetBytes(rHash)
	r.Mod(r, curve.N)
	
	// Calcular R = r * G
	Rx, Ry := curve.ScalarBaseMult(r.Bytes())
	R := &Point{X: Rx, Y: Ry}
	
	// Calcular s = r + SHA512(dom(2) || R || A || message) * a mod N
	h.Reset()
	h.Write(dom)
	h.Write(curve.Marshal(R.X, R.Y)) // R no formato não comprimido
	h.Write(curve.Marshal(priv.X, priv.Y)) // A no formato não comprimido
	h.Write(message)
	hramHash := h.Sum(nil)
	
	hram := new(big.Int).SetBytes(hramHash)
	hram.Mod(hram, curve.N)
	
	s := new(big.Int).Mul(hram, priv.D)
	s.Add(s, r)
	s.Mod(s, curve.N)
	
	return &EdDSASignature{
		R: R,
		S: s,
	}, nil
}

// SignEdDSAASN1 assina uma mensagem e retorna a assinatura no formato ASN.1
func (priv *PrivateKey) SignEdDSAASN1(message []byte) ([]byte, error) {
	sig, err := priv.SignEdDSA(message)
	if err != nil {
		return nil, err
	}
	
	// Converter assinatura para formato ASN.1
	signatureASN1 := struct {
		R []byte
		S *big.Int
	}{
		R: priv.Curve.Marshal(sig.R.X, sig.R.Y),
		S: sig.S,
	}
	
	return asn1.Marshal(signatureASN1)
}

// SignASN1 - compatibilidade com código existente (usa EdDSA internamente)
func (priv *PrivateKey) SignASN1(hash []byte) ([]byte, error) {
	// Para compatibilidade, tratamos o hash como a mensagem
	return priv.SignEdDSAASN1(hash)
}

// VerifyEdDSA verifica uma assinatura EdDSA
func (pub *PublicKey) VerifyEdDSA(message []byte, sig *EdDSASignature) bool {
	curve := pub.Curve
	
	// Dom: contexto específico do domínio (vazio para PureEdDSA)
	dom := []byte{}
	
	// Calcular h = SHA512(dom(2) || R || A || message)
	h := sha512.New()
	h.Write(dom)
	h.Write(curve.Marshal(sig.R.X, sig.R.Y)) // R comprimido
	h.Write(curve.Marshal(pub.X, pub.Y))     // A comprimido
	h.Write(message)
	hramHash := h.Sum(nil)
	
	hram := new(big.Int).SetBytes(hramHash)
	hram.Mod(hram, curve.N)
	
	// Verificar s * G == R + h * A
	sGx, sGy := curve.ScalarBaseMult(sig.S.Bytes())
	hAx, hAy := curve.ScalarMult(pub.X, pub.Y, hram.Bytes())
	
	// Calcular R + h * A
	rhAx, rhAy := curve.Add(sig.R.X, sig.R.Y, hAx, hAy)
	
	// Comparar s * G com R + h * A
	return sGx.Cmp(rhAx) == 0 && sGy.Cmp(rhAy) == 0
}

// VerifyEdDSAASN1 verifica uma assinatura EdDSA no formato ASN.1
func (pub *PublicKey) VerifyEdDSAASN1(message, sigASN1 []byte) bool {
	// Parse da assinatura ASN.1
	var signature struct {
		R []byte
		S *big.Int
	}
	
	_, err := asn1.Unmarshal(sigASN1, &signature)
	if err != nil {
		return false
	}
	
	// Recuperar ponto R
	Rx, Ry := pub.Curve.Unmarshal(signature.R)
	if Rx == nil || Ry == nil {
		return false
	}
	
	sig := &EdDSASignature{
		R: &Point{X: Rx, Y: Ry},
		S: signature.S,
	}
	
	return pub.VerifyEdDSA(message, sig)
}

// VerifyASN1 - compatibilidade com código existente (usa EdDSA internamente)
func (pub *PublicKey) VerifyASN1(hash, sig []byte) bool {
	// Para compatibilidade, tratamos o hash como a mensagem
	return pub.VerifyEdDSAASN1(hash, sig)
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

// ParseSignature analisa uma assinatura ASN.1 e retorna os componentes R e S
func ParseSignature(sig []byte) (*big.Int, *big.Int, error) {
	var signature ECDSASignature
	_, err := asn1.Unmarshal(sig, &signature)
	if err != nil {
		return nil, nil, err
	}
	
	return signature.R, signature.S, nil
}
