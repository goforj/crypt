//go:build ignore
// +build ignore

package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
	"os"
)

func main() {
	// Encrypt encrypts a plaintext using the APP_KEY from environment.

	// Example: encrypt with current APP_KEY
	keyStr, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", keyStr)
	ciphertext, err := crypt.Encrypt("secret")
	godump.Dump(err == nil, ciphertext != "")

	// #bool true
	// #bool true
}
