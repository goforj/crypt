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
	// GenerateKeyToEnv mimics Laravel's key:generate.
	// It generates a new APP_KEY and writes it to the provided .env path.
	// Other keys are preserved; APP_KEY is replaced/added.

	// Example: generate and write APP_KEY to a temp .env
	envPath := filepath.Join(os.TempDir(), ".env")
	key, err := crypt.GenerateKeyToEnv(envPath)
	godump.Dump(err, key)
	// #error <nil>
	// #string "base64:..."
}
