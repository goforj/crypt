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
	tmp := filepath.Join(os.TempDir(), ".env")
	oldKey, _ := crypt.GenerateAppKey()
	_ = os.WriteFile(tmp, []byte("APP_KEY="+oldKey+"\n"), 0o644)
	newKey, err := crypt.RotateKeyInEnv(tmp)
	godump.Dump(err == nil, newKey != "")

	// #bool true
	// #bool true
}
