//go:build ignore
// +build ignore

package main

import (
	"github.com/goforj/crypt"
	"github.com/goforj/godump"
	"os"
	"path/filepath"
)

func main() {
	// RotateKeyInEnv mimics Laravel's key:rotate.
	// It moves the current APP_KEY into APP_PREVIOUS_KEYS (prepended) and writes a new APP_KEY.

	// Example: rotate APP_KEY and prepend old key to APP_PREVIOUS_KEYS
	envPath := filepath.Join(os.TempDir(), ".env")
	currentKey, _ := crypt.GenerateAppKey()
	// Seed a minimal .env with an existing APP_KEY.
	_ = os.WriteFile(envPath, []byte("APP_KEY="+currentKey+"\n"), 0o644)
	newKey, err := crypt.RotateKeyInEnv(envPath)
	godump.Dump(err == nil, newKey != "")
	// #bool true
	// #bool true
}
