//go:build ignore
// +build ignore

package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
	"os"
)

func main() {
	// GetPreviousAppKeys retrieves and parses APP_PREVIOUS_KEYS from the environment.
	// Keys are expected to be comma-delimited and prefixed with "base64:".

	// Example: parse two previous keys (mixed AES-128/256)
	k1, _ := crypt.GenerateAppKey()
	k2, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_PREVIOUS_KEYS", k1+", "+k2)
	keys, err := crypt.GetPreviousAppKeys()
	godump.Dump(len(keys), err)

	// #int 2
	// #error <nil>
}
