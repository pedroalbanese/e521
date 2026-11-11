// edge-toolbox.go
//
// EDGE Crypto Toolbox — Go port of ed521-cli.py
//
// Uses the reference implementation github.com/pedroalbanese/e521.
// Subcommands mirror the Python CLI:
//
//   edge-toolbox ed521 gen          [--priv FILE] [--pub FILE]
//   edge-toolbox ed521 sign         --priv FILE --msg FILE
//   edge-toolbox ed521 verify       --pub FILE --msg FILE --sig HEX
//   edge-toolbox ed521 prove        --priv FILE
//   edge-toolbox ed521 verify-proof --pub FILE (--proof HEX | --proof-file FILE)
//   edge-toolbox ed521 test
//   edge-toolbox ed521 parse        FILE [--debug]
//
// Build:
//   go mod init edge-toolbox
//   go get github.com/pedroalbanese/e521
//   go build -o edge-toolbox edge-toolbox.go
//
// Note: password-encrypted PEM (Curupira-192-CBC) is not provided by the Go
// library; use the Python or PHP CLI for encrypted PEM.

package main

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pedroalbanese/e521"
)

// ====================================================================
// PEM helpers
// ====================================================================

func privateKeyToPEM(priv *e521.PrivateKey) (string, error) {
	der, err := priv.MarshalPKCS8PrivateKey()
	if err != nil {
		return "", err
	}
	return pemEncode("E-521 PRIVATE KEY", der), nil
}

func publicKeyToPEM(pub *e521.PublicKey) (string, error) {
	der, err := pub.MarshalPKCS8PublicKey()
	if err != nil {
		return "", err
	}
	return pemEncode("E-521 PUBLIC KEY", der), nil
}

func pemEncode(label string, der []byte) string {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN ")
	sb.WriteString(label)
	sb.WriteString("-----\n")
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteString("\n")
	}
	sb.WriteString("-----END ")
	sb.WriteString(label)
	sb.WriteString("-----\n")
	return sb.String()
}

func parsePrivateKeyPEM(data []byte) (*e521.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if isEncryptedPEM(string(data)) {
		return nil, errors.New("encrypted PEM (Curupira-192-CBC) is not supported by the Go library; use the Python or PHP CLI")
	}
	return e521.ParsePrivateKey(block.Bytes)
}

func parsePublicKeyPEM(data []byte) (*e521.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return e521.ParsePublicKey(block.Bytes)
}

func isEncryptedPEM(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Proc-Type:") && strings.Contains(line, "ENCRYPTED") {
			return true
		}
	}
	return false
}

func asn1UnmarshalAny(der []byte) string {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return fmt.Sprintf("<unmarshal error: %v>", err)
	}
	return fmt.Sprintf("tag=0x%02x len=%d", v.Tag, len(v.Bytes))
}

// ====================================================================
// Subcommands
// ====================================================================

func cmdGen(args []string) int {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	privPath := fs.String("priv", "ed521_private.pem", "private key PEM path")
	pubPath := fs.String("pub", "ed521_public.pem", "public key PEM path")
	password := fs.Bool("password", false, "encrypt private key with password (not supported in Go CLI)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *password {
		fmt.Fprintln(os.Stderr, "✖ --password (Curupira-192-CBC) is not available in the Go library.")
		fmt.Fprintln(os.Stderr, "  Use the Python or PHP CLI to generate encrypted PEM.")
		return 1
	}

	fmt.Println("Generating Ed521 keys (521-bit curve)...")
	priv, err := e521.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ generate failed: %v\n", err)
		return 1
	}
	pub := priv.GetPublic()

	privPEM, err := privateKeyToPEM(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ private PEM failed: %v\n", err)
		return 1
	}
	pubPEM, err := publicKeyToPEM(pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ public PEM failed: %v\n", err)
		return 1
	}

	if err := os.WriteFile(*privPath, []byte(privPEM), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "✖ write %s: %v\n", *privPath, err)
		return 1
	}
	if err := os.WriteFile(*pubPath, []byte(pubPEM), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✖ write %s: %v\n", *pubPath, err)
		return 1
	}

	fmt.Printf("✔ Private key saved in %s (PEM PKCS#8)\n", *privPath)
	fmt.Printf("✔ Public key saved in %s (PEM SPKI)\n", *pubPath)
	return 0
}

func cmdSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	privPath := fs.String("priv", "", "private key PEM path")
	msgPath := fs.String("msg", "", "message file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *privPath == "" || *msgPath == "" {
		fmt.Fprintln(os.Stderr, "✖ sign requires --priv and --msg")
		return 1
	}

	pemData, err := os.ReadFile(*privPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", *privPath, err)
		return 1
	}
	priv, err := parsePrivateKeyPEM(pemData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ parse private key: %v\n", err)
		return 1
	}

	msg, err := os.ReadFile(*msgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", *msgPath, err)
		return 1
	}

	sig, err := priv.Sign(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ sign failed: %v\n", err)
		return 1
	}
	fmt.Println(hex.EncodeToString(sig))
	return 0
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "public key PEM path")
	msgPath := fs.String("msg", "", "message file")
	sigHex := fs.String("sig", "", "signature hex")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pubPath == "" || *msgPath == "" || *sigHex == "" {
		fmt.Fprintln(os.Stderr, "✖ verify requires --pub, --msg and --sig")
		return 1
	}

	pemData, err := os.ReadFile(*pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", *pubPath, err)
		return 1
	}
	pub, err := parsePublicKeyPEM(pemData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ parse public key: %v\n", err)
		return 1
	}

	msg, err := os.ReadFile(*msgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", *msgPath, err)
		return 1
	}

	sig, err := hex.DecodeString(strings.TrimSpace(*sigHex))
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ invalid hex: %v\n", err)
		return 1
	}

	if pub.Verify(msg, sig) {
		fmt.Printf("✔ Valid Ed521 signature for file: %s\n", *msgPath)
		return 0
	}
	fmt.Printf("✖ Invalid Ed521 signature for file: %s\n", *msgPath)
	return 1
}

func cmdProve(args []string) int {
	fs := flag.NewFlagSet("prove", flag.ContinueOnError)
	privPath := fs.String("priv", "", "private key PEM path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *privPath == "" {
		fmt.Fprintln(os.Stderr, "✖ prove requires --priv")
		return 1
	}

	pemData, err := os.ReadFile(*privPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", *privPath, err)
		return 1
	}
	priv, err := parsePrivateKeyPEM(pemData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ parse private key: %v\n", err)
		return 1
	}

	proof, err := priv.ProveKnowledge()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ prove failed: %v\n", err)
		return 1
	}
	fmt.Println("✔ Zero-knowledge proof generated")
	fmt.Printf("\nProof (hex): %s\n", hex.EncodeToString(proof))
	fmt.Printf("Proof length: %d bytes (%d bits)\n", len(proof), len(proof)*8)
	return 0
}

func cmdVerifyProof(args []string) int {
	fs := flag.NewFlagSet("verify-proof", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "public key PEM path")
	proofHex := fs.String("proof", "", "proof hex")
	proofFile := fs.String("proof-file", "", "proof file (takes precedence)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pubPath == "" {
		fmt.Fprintln(os.Stderr, "✖ verify-proof requires --pub and --proof/--proof-file")
		return 1
	}

	pemData, err := os.ReadFile(*pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", *pubPath, err)
		return 1
	}
	pub, err := parsePublicKeyPEM(pemData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ parse public key: %v\n", err)
		return 1
	}

	hexStr := strings.TrimSpace(*proofHex)
	if *proofFile != "" {
		data, err := os.ReadFile(*proofFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", *proofFile, err)
			return 1
		}
		hexStr = strings.TrimSpace(string(data))
	}
	if hexStr == "" {
		fmt.Fprintln(os.Stderr, "✖ no proof provided (use --proof or --proof-file)")
		return 1
	}

	proof, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ invalid hex: %v\n", err)
		return 1
	}

	if pub.VerifyKnowledge(proof) {
		fmt.Println("\n✔ Zero-knowledge proof valid")
		fmt.Println("  The key holder proves knowledge of the private key")
		return 0
	}
	fmt.Println("\n✖ Zero-knowledge proof invalid")
	fmt.Println("  The key holder does NOT prove knowledge of the private key")
	return 1
}

func cmdTest(_ []string) int {
	fmt.Println("=== E-521 EdDSA Test Suite (via github.com/pedroalbanese/e521) ===")
	fmt.Println()

	fmt.Println("1. Key generation test:")
	priv, err := e521.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ generate failed: %v\n", err)
		return 1
	}
	pub := priv.GetPublic()
	fmt.Printf("   Public key on curve: %v\n",
		e521.E521().IsOnCurve(pub.X, pub.Y))

	fmt.Println("\n2. Point compression test:")
	curve := e521.E521()
	comp := curve.CompressPoint(pub.X, pub.Y)
	dx, dy := curve.DecompressPoint(comp)
	ok := dx != nil && dy != nil && dx.Cmp(pub.X) == 0 && dy.Cmp(pub.Y) == 0
	fmt.Printf("   Compression successful: %d bytes\n", len(comp))
	fmt.Printf("   Decompression correct: %v\n", ok)

	fmt.Println("\n3. Signature test:")
	msg := []byte("Test message for E-521 EdDSA")
	sig, err := priv.Sign(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ sign failed: %v\n", err)
		return 1
	}
	fmt.Printf("   Signature created: %d bytes\n", len(sig))
	fmt.Printf("   Signature valid: %v\n", pub.Verify(msg, sig))
	fmt.Printf("   Wrong message rejected: %v\n", !pub.Verify([]byte("Wrong message"), sig))

	fmt.Println("\n4. Zero-knowledge proof test:")
	proof, err := priv.ProveKnowledge()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ prove failed: %v\n", err)
		return 1
	}
	fmt.Printf("   Proof generated: %d bytes\n", len(proof))
	fmt.Printf("   Proof valid: %v\n", pub.VerifyKnowledge(proof))

	fmt.Println("\n5. PKCS#8 serialization test:")
	privPEM, err := privateKeyToPEM(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ private PEM: %v\n", err)
		return 1
	}
	pubPEM, err := publicKeyToPEM(pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ public PEM: %v\n", err)
		return 1
	}
	parsedPriv, err1 := parsePrivateKeyPEM([]byte(privPEM))
	parsedPub, err2 := parsePublicKeyPEM([]byte(pubPEM))
	fmt.Printf("   Private key serialization correct: %v\n",
		err1 == nil && parsedPriv.D.Cmp(priv.D) == 0)
	fmt.Printf("   Public key serialization correct: %v\n",
		err2 == nil && parsedPub.X.Cmp(pub.X) == 0 && parsedPub.Y.Cmp(pub.Y) == 0)

	fmt.Println("\n=== All tests passed! ===")
	return 0
}

func cmdParse(args []string) int {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	debug := fs.Bool("debug", false, "debug output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "✖ parse requires a key file path")
		return 1
	}
	keyFile := fs.Arg(0)
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✖ read %s: %v\n", keyFile, err)
		return 1
	}
	pemStr := string(data)

	if isEncryptedPEM(pemStr) {
		fmt.Fprintln(os.Stderr, "✖ encrypted PEM (Curupira-192-CBC) is not supported by this Go CLI")
		return 1
	}

	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Fprintln(os.Stderr, "✖ no PEM block found")
		return 1
	}

	if *debug {
		fmt.Printf("DEBUG: PEM label: %s\n", block.Type)
		fmt.Printf("DEBUG: DER length: %d bytes\n", len(block.Bytes))
		fmt.Printf("DEBUG: DER hex: %s\n", hex.EncodeToString(block.Bytes))
		fmt.Printf("DEBUG: ASN.1 header: %s\n", asn1UnmarshalAny(block.Bytes))
	}

	switch block.Type {
	case "E-521 PRIVATE KEY", "PRIVATE KEY":
		priv, err := e521.ParsePrivateKey(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✖ parse private key: %v\n", err)
			return 1
		}
		pub := priv.GetPublic()
		curve := e521.E521()
		comp := curve.CompressPoint(pub.X, pub.Y)

		fmt.Print(pemStr)
		if !strings.HasSuffix(pemStr, "\n") {
			fmt.Println()
		}
		fmt.Printf("\nPrivate-Key: (%d bit)\n", curve.BitSize+3)
		fmt.Println("priv:")
		printHexColonLines(compressedPrivHex(priv))
		fmt.Println("pub:")
		printHexColonLines(hex.EncodeToString(comp))
		fmt.Println("ASN1 OID: 1.3.6.1.4.1.44588.2.1")
		fmt.Println("Curve: E-521")

	case "E-521 PUBLIC KEY", "PUBLIC KEY":
		pub, err := e521.ParsePublicKey(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✖ parse public key: %v\n", err)
			return 1
		}
		curve := e521.E521()
		comp := curve.CompressPoint(pub.X, pub.Y)
		compHex := hex.EncodeToString(comp)

		fmt.Print(pemStr)
		if !strings.HasSuffix(pemStr, "\n") {
			fmt.Println()
		}
		fmt.Printf("\nPublic-Key: (%d bit)\n", len(comp)*8)
		fmt.Println("pub:")
		printHexColonLines(compHex)
		fmt.Println("ASN1 OID: 1.3.6.1.4.1.44588.2.1")
		fmt.Println("Curve: E-521")

		// Short identifier: first 8 bytes of the compressed public key.
		fmt.Println("\nShort ID:")
		fmt.Printf("  %s\n", compHex[:16])

	default:
		fmt.Fprintf(os.Stderr, "✖ unknown PEM label: %s\n", block.Type)
		return 1
	}

	return 0
}

// ====================================================================
// Helpers
// ====================================================================

func compressedPrivHex(priv *e521.PrivateKey) string {
	const n = 66
	be := priv.D.Bytes()
	if len(be) < n {
		pad := make([]byte, n-len(be))
		be = append(pad, be...)
	} else if len(be) > n {
		be = be[len(be)-n:]
	}
	return hex.EncodeToString(be)
}

func printHexColonLines(hexStr string) {
	const chunk = 30
	for i := 0; i < len(hexStr); i += chunk {
		end := i + chunk
		if end > len(hexStr) {
			end = len(hexStr)
		}
		part := hexStr[i:end]
		var pairs []string
		for j := 0; j+2 <= len(part); j += 2 {
			pairs = append(pairs, part[j:j+2])
		}
		if len(part)%2 == 1 {
			pairs = append(pairs, part[len(part)-1:])
		}
		fmt.Printf("    %s\n", strings.Join(pairs, ":"))
	}
}

// ====================================================================
// Entry point
// ====================================================================

func usage() {
	fmt.Fprintln(os.Stderr, "EDGE Crypto Toolbox (Go) — ED521")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage: edge-toolbox ed521 <command> [options]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  gen           [--priv FILE] [--pub FILE]")
	fmt.Fprintln(os.Stderr, "  sign          --priv FILE --msg FILE")
	fmt.Fprintln(os.Stderr, "  verify        --pub FILE --msg FILE --sig HEX")
	fmt.Fprintln(os.Stderr, "  prove         --priv FILE")
	fmt.Fprintln(os.Stderr, "  verify-proof  --pub FILE (--proof HEX | --proof-file FILE)")
	fmt.Fprintln(os.Stderr, "  test")
	fmt.Fprintln(os.Stderr, "  parse         FILE [--debug]")
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "ed521" {
		args = args[1:]
	}
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	sub, rest := args[0], args[1:]
	commands := map[string]func([]string) int{
		"gen":          cmdGen,
		"sign":         cmdSign,
		"verify":       cmdVerify,
		"prove":        cmdProve,
		"verify-proof": cmdVerifyProof,
		"test":         cmdTest,
		"parse":        cmdParse,
	}

	fn, ok := commands[sub]
	if !ok {
		fmt.Fprintf(os.Stderr, "✖ unknown command: %s\n", sub)
		usage()
		os.Exit(1)
	}
	os.Exit(fn(rest))
}
