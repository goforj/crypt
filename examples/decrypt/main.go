//go:build ignore
// +build ignore

package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
	"os"
)

func main() {
	// Decrypt decrypts an encrypted payload using the APP_KEY from environment.
	// Falls back to APP_PREVIOUS_KEYS when the current key cannot decrypt.

	// Example: decrypt using current key
	keyStr, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", keyStr)
	c, _ := crypt.Encrypt("secret")
	p, _ := crypt.Decrypt(c)
	godump.Dump(p)

	// #string "secret"

	// Example: decrypt ciphertext encrypted with a previous key
	oldKeyStr, _ := crypt.GenerateAppKey()
	newKeyStr, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", oldKeyStr)
	oldCipher, _ := crypt.Encrypt("rotated")
	_ = os.Setenv("APP_KEY", newKeyStr)
	_ = os.Setenv("APP_PREVIOUS_KEYS", oldKeyStr)
	plain, err := crypt.Decrypt(oldCipher)
	godump.Dump(plain, err)

	// #string "rotated"
	// #error <nil>
}
