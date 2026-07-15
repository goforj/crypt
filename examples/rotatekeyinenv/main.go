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
	// RotateKeyInEnv writes a new APP_KEY and prepends the old key to APP_PREVIOUS_KEYS.

	// Same-path calls are serialized within this process so concurrent rotations retain
	// every key. Atomic replacement prevents partial files, but unrelated processes must
	// still coordinate their read-modify-write operations with the caller. If the atomic
	// rename commits but syncing its directory fails, the installed key is returned with
	// the error so callers do not lose track of active key material.

	// Example: rotate APP_KEY while retaining the previous key
	dir, _ := os.MkdirTemp("", "crypt-rotate-*")
	defer os.RemoveAll(dir)
	envPath := filepath.Join(dir, ".env")
	currentKey, _ := crypt.GenerateAppKey()
	// Seed a minimal .env with an existing APP_KEY.
	_ = os.WriteFile(envPath, []byte("APP_KEY="+currentKey+"\n"), 0o600)
	newKey, err := crypt.RotateKeyInEnv(envPath)
	godump.Dump(err == nil, newKey != "")
	// #bool true
	// #bool true
}
