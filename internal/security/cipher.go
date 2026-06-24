package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrInvalidNonceSize  = errors.New("cipher invalid nonce size")
	ErrCipherRequiredKey = errors.New("cipher key is required")
)

type Cipher struct {
	SecretKey string
}

func NewCipher(key string) (*Cipher, error) {
	if strings.TrimSpace(key) == "" {
		return nil, ErrCipherRequiredKey
	}
	return &Cipher{
		SecretKey: key,
	}, nil
}

func (c *Cipher) Encrypt(text string) (string, error) {
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, err := hex.DecodeString(c.SecretKey)
	if err != nil {
		return "", fmt.Errorf("security.chiper.Encrypt: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("security.chiper.Encrypt: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("security.chiper.Encrypt: %w", err)
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("security.chiper.Encrypt: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(text), nil)

	encodedNonce := hex.EncodeToString(nonce)
	encodedCiphertext := hex.EncodeToString(ciphertext)
	return encodedNonce + ":" + encodedCiphertext, nil
}

func (c *Cipher) Decrypt(encryptedText string) (string, error) {
	key, err := hex.DecodeString(c.SecretKey)
	if err != nil {
		return "", fmt.Errorf("security.chiper.Decrypt: %w", err)
	}
	textParts := strings.Split(encryptedText, ":")
	if len(textParts) != 2 {
		return "", fmt.Errorf("security.chiper.Decrypt: invalid encrypted text: %s", encryptedText)
	}
	text, err := hex.DecodeString(textParts[1])
	if err != nil {
		return "", fmt.Errorf("security.chiper.Decrypt: %w", err)
	}
	nonce, err := hex.DecodeString(textParts[0])
	if err != nil {
		return "", fmt.Errorf("security.chiper.Decrypt: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("security.chiper.Decrypt: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("security.chiper.Decrypt: %w", err)
	}

	if len(nonce) != aesgcm.NonceSize() {
		return "", ErrInvalidNonceSize
	}

	plaintext, err := aesgcm.Open(nil, nonce, text, nil)
	if err != nil {
		return "", fmt.Errorf("security.chiper.Decrypt: %w", err)
	}

	return string(plaintext), nil
}
