package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"math/big"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// IsValidSignature returns true if the given signature is a valid SHA256withECDSA signature for the given payload  with
//the binding public key and false otherwise. It returns an error if either the signature or the public key are invalid
func IsValidSignature(publicKeyValue string, payload string, signature string) (bool, error) {
	publicKey, err := getEcdsaPublicKey(publicKeyValue)
	if err != nil {
		return false, err
	}
	parsedSignature, err := signatureToEcdsaSignature(signature)
	if err != nil {
		return false, err
	}
	payloadHash := sha256.Sum256([]byte(payload))
	return ecdsa.Verify(publicKey, payloadHash[:], parsedSignature.R, parsedSignature.S), nil
}
func signatureToEcdsaSignature(signature string) (*ecdsaSignature, error) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	parsedSignature := &ecdsaSignature{}
	rest, err := asn1.Unmarshal(signatureBytes, parsedSignature)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, stderrors.New("unexpected extra information in the signature")
	}
	return parsedSignature, nil
}
func getEcdsaPublicKey(publicKeyValue string) (*ecdsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(publicKeyValue)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, stderrors.New("unexpected public key type")
	}
	return publicKey, nil
}

func main() {
	pub := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXldnFlPj+csEDSavdHMfksRN701h7ThJ8OdIDxOkQpiDwbrNVkxiETgCDv5erLoq/4EZLEKG40umAna6KTTsHw=="
	text := "AC513af03f3228f1e8558cebba01dc0b3eIS0fc704bd7366ad0eacf2f3d5d17bae7aYE2feb7974c17eb780ba378a756aba8e9fYF03605763dd8897ee2bf7dab423f52e92YC036cbec9257bb962a0baba8cc444b7922020-03-05T19:11:23Z2020-03-05T19:11:23Zpending{\"message\": \"test\"}"
	// MEYCIQD9Q9h9DxbbwtneFCpPCH9O4SX8oNPush0emvN0A6mKvAIhANs+sGfOY6OaY9Fw74V3eNVJFmWBjyD+/4niFtxF/14c
	// PZPu4jyNoK8y/4tVofAgYnwD3dWpz2S+4Y+1NAuuHstrFqjBH5OP4/vqoX4vtT2zrHLZFI0c/E9kX9y16Wntsg==
	signature := "MEUCIHZEw7ya74G6CfkpCzQPDsfQt++xTdmyfm0Kk6CloTgJAiEAtuBZgld/NZAuZOEegQVOCqfcnyBtKY9cmDOnXmLGOe8="
	result, err := IsValidSignature(pub, text, signature)
	if err != nil {
		panic(err)
	}
	fmt.Println(result)
}
