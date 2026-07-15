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
	// EncryptLaravel encrypts plaintext with APP_KEY in Laravel's encryptString CBC format.
	// This explicit opt-in avoids silently changing the existing Encrypt wire format.

	// Example: emit a Laravel-compatible ciphertext from APP_KEY
	appKey, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", appKey)
	ciphertext, err := crypt.EncryptLaravel("secret")
	godump.Dump(err == nil, ciphertext != "")
	// #bool true
	// #bool true
}
