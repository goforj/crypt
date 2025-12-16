//go:build ignore
// +build ignore

package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
	"os"
)

func main() {
	// GetAppKey retrieves the APP_KEY from the environment and parses it.

	// Example: read APP_KEY and ensure the correct size
	keyStr, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", keyStr)
	key, err := crypt.GetAppKey()
	godump.Dump(len(key), err)

	// #int 32
	// #error <nil>
}
