//go:build ignore
// +build ignore

// Package main keeps a crypt API example runnable so documentation changes remain compile-checked.
package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"

	"os"
)

// main keeps the generated API example executable so documentation drift fails during compilation.
func main() {
	// Decrypt decrypts either supported payload format using APP_KEY and APP_PREVIOUS_KEYS.

	// Example: decrypt using current key
	appKey, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", appKey)
	ciphertext, _ := crypt.Encrypt("secret")
	plaintext, _ := crypt.Decrypt(ciphertext)
	godump.Dump(plaintext)
	// #string "secret"

	// Example: decrypt ciphertext encrypted with a previous key
	oldAppKey, _ := crypt.GenerateAppKey()
	newAppKey, _ := crypt.GenerateAppKey()

	// Encrypt with the old key first.
	_ = os.Setenv("APP_KEY", oldAppKey)
	rotatedCiphertext, _ := crypt.Encrypt("rotated")

	// Rotate to a new current key, but keep the old key in APP_PREVIOUS_KEYS.
	_ = os.Setenv("APP_KEY", newAppKey)
	_ = os.Setenv("APP_PREVIOUS_KEYS", oldAppKey)
	plaintext, err := crypt.Decrypt(rotatedCiphertext)
	godump.Dump(plaintext, err)
	// #string "rotated"
	// #error <nil>
}
