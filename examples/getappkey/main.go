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
	// GetAppKey retrieves the APP_KEY from the environment and parses it.

	// Example: read APP_KEY and ensure the correct size
	appKey, _ := crypt.GenerateAppKey()
	_ = os.Setenv("APP_KEY", appKey)
	key, err := crypt.GetAppKey()
	godump.Dump(len(key), err)
	// #int 32
	// #error <nil>
}
