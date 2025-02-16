package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize = 16
	keySize  = 32
)

// Generate password using argon2
func GenerateKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, keySize)
}

// Encrypt with ARS-GCM
func Encrypt(text, password string) (string, error) {
	salt := make([]byte, saltSize)

	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := GenerateKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(append(salt, cipherText...)), nil
}

// Decrypt AES-GCM encrypted text
func Decrypt(encryptedText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedText)

	if err != nil {
		return "", err
	}

	salt := data[:saltSize]
	cipherText := data[saltSize:]

	key := GenerateKey(password, salt)
	block, err := aes.NewCipher(key)

	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)

	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)

	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
