package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

type Hmac struct {
	secretKey string
}

func NewHmac(secretKey string) *Hmac {
	return &Hmac{
		secretKey: secretKey,
	}
}

func (h *Hmac) Sign(data string) (hash string) {
	hmac := hmac.New(sha256.New, []byte(h.secretKey))
	_, _ = hmac.Write([]byte(data))
	return hex.EncodeToString(hmac.Sum(nil))
}
