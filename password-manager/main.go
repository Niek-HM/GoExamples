package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

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

// Save password
func SavePassword(filename, password, masterKey string) {
	encrypted, err := Encrypt(password, masterKey)

	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}

	f, _ := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()

	f.WriteString(encrypted + "\n")
	fmt.Println("Password saved successfully!")
}

// Load passwords
func LoadPasswords(filename, masterKey string) {
	data, err := os.ReadFile(filename)

	if err != nil {
		fmt.Println("No saved passwords.")
		return
	}

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if len(line) > 0 {
			decrypted, err := Decrypt(line, masterKey)
			if err != nil {
				fmt.Println("Error decrypting:", err)
				continue
			}

			fmt.Println("Password:", decrypted)
		}
	}
}

// Main function
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <command>")
		fmt.Println("Commands: save <password> | load")
		return
	}

	masterKey := "super-secure-master-key" // Set with user imput
	filename := "vault.enc"

	switch os.Args[1] {
	case "save":
		if len(os.Args) < 3 {
			fmt.Println("Usage: save <password>")
			return
		}

		SavePassword(filename, os.Args[2], masterKey)

	case "load":
		LoadPasswords(filename, masterKey)

	default:
		fmt.Println("Unknown command")
	}
}
