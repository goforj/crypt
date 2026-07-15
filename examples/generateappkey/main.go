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
	// GenerateAppKey generates a random AES-256 key using Laravel's base64-prefixed key syntax.

	// Example: generate an AES-256 key
	key, _ := crypt.GenerateAppKey()
	godump.Dump(key)
	// #string "base64:..."
}
