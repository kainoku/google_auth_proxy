package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

func EncryptWithAES(secret string, value string) (string, error) {

	target := []byte(value)

	// make an initialization vector.
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// generate secret bytes
	secretBytes := []byte(secret)
	block, err := aes.NewCipher(secretBytes[:])
	if err != nil {
		return "", err
	}

	// encrypt
	encrypted := make([]byte, len(target))
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(encrypted, target)

	return base64.URLEncoding.EncodeToString(append(iv, encrypted...)), nil
}
