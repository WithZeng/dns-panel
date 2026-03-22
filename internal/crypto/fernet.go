package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

func IsFernetToken(s string) bool {
	return strings.HasPrefix(s, "gAAAAA")
}

func DecryptFernet(token string, fernetKey string) (string, error) {
	keyBytes, err := base64.URLEncoding.DecodeString(fernetKey)
	if err != nil {
		return "", errors.New("invalid fernet key encoding")
	}
	if len(keyBytes) != 32 {
		return "", errors.New("fernet key must be 32 bytes (signing 16 + encryption 16)")
	}
	signingKey := keyBytes[:16]
	encryptionKey := keyBytes[16:]

	tokenBytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", errors.New("invalid fernet token encoding")
	}

	// Fernet format: version(1) + timestamp(8) + iv(16) + ciphertext(N) + hmac(32)
	if len(tokenBytes) < 57 { // 1+8+16+32 minimum
		return "", errors.New("fernet token too short")
	}

	if tokenBytes[0] != 0x80 {
		return "", errors.New("unsupported fernet version")
	}

	hmacStart := len(tokenBytes) - 32
	payload := tokenBytes[:hmacStart]
	expectedMAC := tokenBytes[hmacStart:]

	mac := hmac.New(sha256.New, signingKey)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), expectedMAC) {
		return "", errors.New("fernet HMAC verification failed - wrong key?")
	}

	iv := tokenBytes[9:25]
	ct := tokenBytes[25:hmacStart]

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ct))
	mode.CryptBlocks(plaintext, ct)

	// PKCS7 unpad
	if len(plaintext) == 0 {
		return "", errors.New("empty plaintext")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(plaintext) {
		return "", errors.New("invalid PKCS7 padding")
	}
	for _, b := range plaintext[len(plaintext)-padLen:] {
		if int(b) != padLen {
			return "", errors.New("invalid PKCS7 padding bytes")
		}
	}
	plaintext = plaintext[:len(plaintext)-padLen]

	return string(plaintext), nil
}
