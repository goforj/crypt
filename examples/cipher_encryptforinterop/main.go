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
	// EncryptForInterop encrypts plaintext with the Cipher's current key using the interoperability CBC envelope.
	// The envelope signs the base64 IV and ciphertext, encodes the MAC as lowercase hex, and includes an empty tag.
	// This explicit opt-in leaves Encrypt's established wire format unchanged.

	// Example: emit an interoperability ciphertext with an injected key
	key := make([]byte, 32)
	c, _ := crypt.New(key)
	ciphertext, err := c.EncryptForInterop("secret")
	godump.Dump(err == nil, ciphertext != "")
	// #bool true
	// #bool true
}
