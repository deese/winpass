package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strconv"
)

const defaultPasswordLength = 25
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

const charsetNoSymbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Environment variables compatible with pass
const (
	envGeneratedLength      = "PASSWORD_STORE_GENERATED_LENGTH"
	envCharacterSet         = "PASSWORD_STORE_CHARACTER_SET"
	envCharacterSetNoSymbol = "PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS"
	envClipTime             = "PASSWORD_STORE_CLIP_TIME"
)

// envPositiveInt reads a positive integer from the environment, or returns def if unset.
func envPositiveInt(name string, def int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("invalid %s: %q (expected a positive integer)", name, raw)
	}
	return n, nil
}

// charsetFor returns the characters to draw from. The environment overrides
// use literal characters (pass accepts tr(1) syntax such as [:alnum:], which is not supported).
func charsetFor(symbols bool) string {
	name, def := envCharacterSet, charset
	if !symbols {
		name, def = envCharacterSetNoSymbol, charsetNoSymbols
	}
	if custom := os.Getenv(name); custom != "" {
		return custom
	}
	return def
}

func generatePassword(length int, symbols bool) (string, error) {
	chars := []rune(charsetFor(symbols))
	buf := make([]rune, length)
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
