//go:build ignore
// +build ignore

package main

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
)

func main() {
	// ReadAppKey parses a base64 encoded app key with "base64:" prefix.
	// Accepts 16-byte keys (AES-128) or 32-byte keys (AES-256) after decoding.

	// Example: parse AES-128 and AES-256 keys
	key128raw := make([]byte, 16)
	_, _ = rand.Read(key128raw)
	key128str := "base64:" + base64.StdEncoding.EncodeToString(key128raw)

	key256str, _ := crypt.GenerateAppKey()

	key128, _ := crypt.ReadAppKey(key128str)
	key256, _ := crypt.ReadAppKey(key256str)
	godump.Dump(len(key128), len(key256))

	// #int 16
	// #int 32
}
