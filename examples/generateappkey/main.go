//go:build ignore
// +build ignore

package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
)

func main() {
	// GenerateAppKey generates a random base64 app key prefixed with "base64:".

	// Example: generate an AES-256 key
	key, _ := crypt.GenerateAppKey()
	godump.Dump(key)

	// #string "base64:..."
}
