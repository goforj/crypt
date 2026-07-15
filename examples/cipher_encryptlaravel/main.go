//go:build ignore
// +build ignore

// Package main keeps a crypt API example runnable so documentation changes remain compile-checked.
package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
)

// main keeps the generated API example executable so documentation drift fails during compilation.
func main() {
	// EncryptLaravel encrypts plaintext with the Cipher's current key in Laravel's encryptString format.
	// The result can be consumed by Laravel 12 AES-128-CBC or AES-256-CBC encrypters.

	// Example: emit a Laravel-compatible ciphertext with an injected key
	key := make([]byte, 32)
	c, _ := crypt.New(key)
	ciphertext, err := c.EncryptLaravel("secret")
	godump.Dump(err == nil, ciphertext != "")
	// #bool true
	// #bool true
}
