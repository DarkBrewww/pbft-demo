// Create this file at: crypto/keys.go
package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadPrivateKey loads a single PEM-encoded EC private key from file
func LoadPrivateKey(nodeID int) (*ecdsa.PrivateKey, error) {
	fileName := fmt.Sprintf("key%d.priv", nodeID)
	keyData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file %s: %w", fileName, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block from %s", fileName)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDSA private key")
	}
	return ecKey, nil
}

// LoadAllPublicKeys loads all N public keys into a map
func LoadAllPublicKeys(numNodes int) (map[int]*ecdsa.PublicKey, error) {
	pubKeys := make(map[int]*ecdsa.PublicKey)
	for i := 0; i < numNodes; i++ {
		fileName := fmt.Sprintf("key%d.pub", i)
		keyData, err := os.ReadFile(fileName)
		if err != nil {
			return nil, fmt.Errorf("could not read public key file %s: %w", fileName, err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil || block.Type != "EC PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block from %s", fileName)
		}

		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an ECDSA public key")
		}
		pubKeys[i] = ecKey
	}
	return pubKeys, nil
}
