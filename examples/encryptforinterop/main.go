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
	// EncryptForInterop encrypts plaintext with APP_KEY using the interoperability CBC envelope.
	// The envelope signs the base64 IV and ciphertext, encodes the MAC as lowercase hex, and includes an empty tag.
	// This explicit opt-in avoids silently changing the existing Encrypt wire format.

	// Example: emit an interoperability ciphertext from APP_KEY
	appKey, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", appKey)
	ciphertext, err := crypt.EncryptForInterop("secret")
	godump.Dump(err == nil, ciphertext != "")
	// #bool true
	// #bool true
}
