// Create this file at: cmd/keygen/main.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand" // <-- THE MISSING IMPORT
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

const NumNodes = 7

func main() {
	log.Println("Generating key pairs...")
	curve := elliptic.P256()

	for i := 0; i < NumNodes; i++ {
		// 1. Generate a new private key
		// *** THIS IS THE FIX: Use rand.Reader instead of nil ***
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate private key for node %d: %v", i, err)
		}

		// --- Save Private Key to file (e.g., key0.priv) ---

		// 2. Marshal private key to PKCS8 format
		privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			log.Fatalf("Failed to marshal private key for node %d: %v", i, err)
		}

		// 3. Create a PEM block
		privPem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		}

		// 4. Write to file
		privFileName := fmt.Sprintf("key%d.priv", i)
		privFile, err := os.Create(privFileName)
		if err != nil {
			log.Fatalf("Failed to create file %s: %v", privFileName, err)
		}
		if err := pem.Encode(privFile, privPem); err != nil {
			log.Fatalf("Failed to write to file %s: %v", privFileName, err)
		}
		privFile.Close()

		// --- Save Public Key to file (e.g., key0.pub) ---

		// 5. Marshal public key to PKIX format
		pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			log.Fatalf("Failed to marshal public key for node %d: %v", i, err)
		}

		// 6. Create a PEM block
		pubPem := &pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubBytes,
		}

		// 7. Write to file
		pubFileName := fmt.Sprintf("key%d.pub", i)
		pubFile, err := os.Create(pubFileName)
		if err != nil {
			log.Fatalf("Failed to create file %s: %v", pubFileName, err)
		}
		if err := pem.Encode(pubFile, pubPem); err != nil {
			log.Fatalf("Failed to write to file %s: %v", pubFileName, err)
		}
		pubFile.Close()
	}
	log.Printf("Successfully generated and saved %d key pairs.", NumNodes)
}
