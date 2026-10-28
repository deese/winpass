package main

import (
	"crypto/rand"
	"math/big"
)

const defaultPasswordLength = 25
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

func generatePassword(length int) (string, error) {
	buf := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := range buf {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		buf[i] = charset[idx.Int64()]
	}
	return string(buf), nil
}
