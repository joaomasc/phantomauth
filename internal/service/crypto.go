package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// validatePasswordStrength verifica complexidade da senha (diretrizes owasp):
// min 8 chars, pelo menos 1 maiuscula, 1 minuscula, 1 digito, 1 caractere especial.
func validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("senha deve ter pelo menos 8 caracteres")
	}
	// bcrypt silenciosamente trunca em 72 bytes
	if len(password) > 72 {
		return errors.New("senha nao pode exceder 72 caracteres")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "letra maiuscula")
	}
	if !hasLower {
		missing = append(missing, "letra minuscula")
	}
	if !hasDigit {
		missing = append(missing, "digito")
	}
	if !hasSpecial {
		missing = append(missing, "caractere especial (!@#$...)")
	}

	if len(missing) > 0 {
		return fmt.Errorf("senha fraca - faltando: %s", strings.Join(missing, ", "))
	}

	return nil
}

// encryptTOTPSecret criptografa o segredo totp com aes-256-gcm antes de persistir.
// o nonce e prefixado ao ciphertext.
func encryptTOTPSecret(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("rand nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptTOTPSecret descriptografa o segredo totp armazenado no db.
func decryptTOTPSecret(encrypted string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("gcm.Open: %w", err)
	}

	return string(plaintext), nil
}
