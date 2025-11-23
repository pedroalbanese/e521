# E-521 🇧🇷
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/e521/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/e521?status.png)](http://godoc.org/github.com/pedroalbanese/e521)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/e521)](https://goreportcard.com/report/github.com/pedroalbanese/e521)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/e521)](https://github.com/pedroalbanese/e521/releases)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.17290170-blue.svg)](https://doi.org/10.5281/zenodo.17290170)

#### ITI DOC-ICP-01.01 — Brazilian Cryptographic Standards for Public-Key Algorithms  
Brazil's national public key cryptographic standards are defined in the **DOC-ICP-01.01**, issued by the **Instituto Nacional de Tecnologia da Informação (ITI)** under the **ICP-Brasil** framework. This standard mandates the use of internationally recognized and security-reviewed asymmetric algorithms, including:

- **EdDSA over Curve E-521**, defined as a high-security elliptic curve consistent with 256-bit security strength, considered for future-safe digital signatures mechanism.

This algorithm is officially approved through the **Instrução Normativa ITI nº 22, de 23 de março de 2022**, which consolidates and updates the cryptographic requirements under Brazilian law, ensuring strong digital security for certificates and signatures in national electronic documents and transactions.

Diego F. Aranha, Paulo S. L. M. Barreto, Geovandro C. C. F. Pereira, Jefferson Ricardini. "A note on high-security general-purpose elliptic curves." 2013. https://eprint.iacr.org/2013/647

**Source:**  
[ICP-Brasil – DOC-ICP-01.01, v5.0 (2022)](https://repositorio.iti.gov.br/instrucoes-normativas/IN2022_22_DOC-ICP-01.01.htm)  
Instrução Normativa ITI nº 22/2022 – Instituto Nacional de Tecnologia da Informação  
OID Ed521: 1.3.6.1.4.1.44588.2.1

#### Usage
```go
package main

import (
	"fmt"
	"log"

	"github.com/pedroalbanese/e521"
)

func main() {
	// === 1. Generate Key Pair ===
	privKey, err := e521.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}
	pubKey := privKey.GetPublic()

	fmt.Println("Private and public keys generated successfully.")

	// === 2. Sign a message ===
	message := []byte("Test message for digital signature")
	signature, err := privKey.SignASN1Compressed(message)
	if err != nil {
		log.Fatalf("Error signing message: %v", err)
	}
	fmt.Printf("Generated signature (ASN.1): %x\n", signature)

	// === 3. Verify signature ===
	isValid := pubKey.VerifyASN1Compressed(message, signature)
	fmt.Printf("Is signature valid? %v\n", isValid)
}
```

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2025 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
