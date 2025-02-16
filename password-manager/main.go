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
	saltSize   = 16
	keySize    = 32
	masterFile = "master.key" // File where the master key is encrypted
	vaultFile  = "vault.enc"  // File where encrypted passwords are stored
)

// Generate a key using Argon2
func GenerateKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, keySize)
}

// Encrypt text using AES-GCM
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

// Save the master key securely
func SaveMasterKey(password string) {
	var masterPassword string
	fmt.Print("Set a master password: ")
	fmt.Scanln(&masterPassword)

	encryptedMaster, err := Encrypt(masterPassword, password)
	if err != nil {
		fmt.Println("Error encrypting master key:", err)
		return
	}

	os.WriteFile(masterFile, []byte(encryptedMaster), 0600)
	fmt.Println("Master password saved securely!")
}

// Load the master key
func LoadMasterKey(password string) (string, error) {
	data, err := os.ReadFile(masterFile)
	if err != nil {
		return "", fmt.Errorf("no master key found, run 'init' first")
	}

	return Decrypt(string(data), password)
}

// Save encrypted password
func SavePassword(masterPassword, newPassword string) {
	encrypted, err := Encrypt(newPassword, masterPassword)
	if err != nil {
		fmt.Println("Error encrypting password:", err)
		return
	}

	f, _ := os.OpenFile(vaultFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	defer f.Close()
	f.WriteString(encrypted + "\n")
	fmt.Println("Password saved securely!")
}

// Load and decrypt stored passwords
func LoadPasswords(masterPassword string) {
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		fmt.Println("No saved passwords yet.")
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if len(line) > 0 {
			decrypted, err := Decrypt(line, masterPassword)
			if err != nil {
				fmt.Println("Error decrypting:", err)
				continue
			}
			fmt.Println("Password:", decrypted)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <command>")
		fmt.Println("Commands: init | save <password> | load")
		return
	}

	var systemPassword string
	fmt.Print("Enter system password: ")
	fmt.Scanln(&systemPassword)

	switch os.Args[1] {

	case "init":
		SaveMasterKey(systemPassword)

	case "save":
		masterKey, err := LoadMasterKey(systemPassword)

		if err != nil {
			fmt.Println(err)
			return
		}

		if len(os.Args) < 3 {
			fmt.Println("Usage: save <password>")
			return
		}
		SavePassword(masterKey, os.Args[2])

	case "load":
		masterKey, err := LoadMasterKey(systemPassword)

		if err != nil {
			fmt.Println(err)
			return
		}
		LoadPasswords(masterKey)

	default:
		fmt.Println("Unknown command")
	}
}
