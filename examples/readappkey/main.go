//go:build ignore
// +build ignore

// Package main keeps a crypt API example runnable so documentation changes remain compile-checked.
package main

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/goforj/crypt"
	"github.com/goforj/godump"
)

// main keeps the generated API example executable so documentation drift fails during compilation.
func main() {
	// ReadAppKey parses a base64-prefixed AES-128 or AES-256 application key.

	// Example: parse AES-128 and AES-256 keys
	// Build a 16-byte (AES-128) key string manually.
	raw16 := make([]byte, 16)
	_, _ = rand.Read(raw16)
	key16 := "base64:" + base64.StdEncoding.EncodeToString(raw16)

	// Generate a 32-byte (AES-256) key string with the helper.
	key32, _ := crypt.GenerateAppKey()

	parsed16, _ := crypt.ReadAppKey(key16)
	parsed32, _ := crypt.ReadAppKey(key32)
	godump.Dump(len(parsed16), len(parsed32))
	// #int 16
	// #int 32
}
