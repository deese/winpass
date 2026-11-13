package main

import (
	"crypto/rand"
	"math/big"
)

const defaultPasswordLength = 25
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

const charsetNoSymbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generatePassword(length int, symbols bool) (string, error) {
	chars := charset
	if !symbols {
		chars = charsetNoSymbols
	}
	buf := make([]byte, length)
	charsetLen := big.NewInt(int64(len(chars)))
	for i := range buf {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		buf[i] = chars[idx.Int64()]
	}
	return string(buf), nil
}
