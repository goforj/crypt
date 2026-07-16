//go:build ignore
// +build ignore

// Package main keeps a crypt API example runnable so documentation changes remain compile-checked.
package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"

	"os"
	"path/filepath"
)

// main keeps the generated API example executable so documentation drift fails during compilation.
func main() {
	// GenerateKeyToEnv creates a new APP_KEY and destructively clears APP_PREVIOUS_KEYS.

	// This operation is a reset, not a graceful rotation. Existing ciphertext that
	// requires a cleared previous key becomes unreadable; use RotateKeyInEnv to retain
	// decryption history. New files use mode 0600, while existing file permissions are
	// preserved. Final-component symlinks are rejected. If the atomic rename commits but
	// syncing its directory fails, the installed key is returned together with the error.

	// Example: reset APP_KEY in a temporary env file
	dir, _ := os.MkdirTemp("", "crypt-reset-*")
	defer os.RemoveAll(dir)
	envPath := filepath.Join(dir, ".env")
	key, err := crypt.GenerateKeyToEnv(envPath)
	godump.Dump(err, key)
	// #error <nil>
	// #string "base64:..."
}
