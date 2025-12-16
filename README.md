<p align="center">
  <img src="./docs/images/logo.png?v=2" width="400" alt="crypt logo">
</p>

<p align="center">
    Laravel-compatible symmetric encryption for Go - AES-128/256 CBC with HMAC, key rotation, and portable payloads.
</p>

<p align="center">
    <a href="https://pkg.go.dev/github.com/goforj/crypt"><img src="https://pkg.go.dev/badge/github.com/goforj/crypt.svg" alt="Go Reference"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://github.com/goforj/crypt/actions"><img src="https://github.com/goforj/crypt/actions/workflows/test.yml/badge.svg" alt="Go Test"></a>
    <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.18+-blue?logo=go" alt="Go version"></a>
    <img src="https://img.shields.io/github/v/tag/goforj/crypt?label=version&sort=semver" alt="Latest tag">
    <a href="https://codecov.io/gh/goforj/crypt" ><img src="https://codecov.io/github/goforj/crypt/graph/badge.svg?token=Z8NM86Q50C"/></a>
    <a href="https://goreportcard.com/report/github.com/goforj/crypt"><img src="https://goreportcard.com/badge/github.com/goforj/crypt" alt="Go Report Card"></a>
</p>

<p align="center">
  <code>crypt</code> mirrors Laravel's encryption format so Go services can read and write the same ciphertext as PHP apps. It signs every payload with an HMAC and supports graceful key rotation via <code>APP_PREVIOUS_KEYS</code>.
</p>

# Features

- 🔐 AES-128/256-CBC + HMAC-SHA256 payloads identical to Laravel
- ♻️ Key rotation: decrypt falls back through `APP_PREVIOUS_KEYS`
- 🔑 `base64:` key parsing (16- or 32-byte keys)
- 🧪 Focused, table-driven tests for tampering, rotation, and key sizes
- 📦 Zero dependencies beyond the Go standard library

## Install

```bash
go get github.com/goforj/crypt
```

## Quickstart

```go
package main

import (
	"fmt"
	"os"

	"github.com/goforj/crypt"
)

func main() {
	// Typical Laravel-style key: base64 + 32 bytes (AES-256) or 16 bytes (AES-128).
	if err := os.Setenv("APP_KEY", "base64:..."); err != nil {
		panic(err)
	}

	ciphertext, err := crypt.Encrypt("secret")
	if err != nil {
		panic(err)
	}

	plaintext, err := crypt.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext) // "secret"
}
```

## Key format and rotation

- `APP_KEY` **must** be prefixed with `base64:` and decode to **16 bytes (AES-128)** or **32 bytes (AES-256)**.
- `APP_PREVIOUS_KEYS` is optional; provide a comma-delimited list of older keys (same format).  
  Decrypt will try the current key first, then each previous key until one succeeds.
- Encrypt **always** uses the current `APP_KEY`; no auto re-encrypt is performed on decrypt.

Example:

```bash
export APP_KEY="base64:J63qRTDLub5NuZvP+kb8YIorGS6qFYHKVo6u7179stY="
export APP_PREVIOUS_KEYS="base64:2nLsGFGzyoae2ax3EF2Lyq/hH6QghBGLIq5uL+Gp8/w="
```

## CLI helpers

Generate a Laravel-style key:

```go
k, _ := crypt.GenerateAppKey()
fmt.Println(k) // base64:...
```

Parse an existing key string:

```go
keyBytes, err := crypt.ReadAppKey("base64:...") // len == 16 or 32
```

## Behavior parity with Laravel

- AES-CBC with PKCS#7 padding
- HMAC-SHA256 over IV + ciphertext
- JSON payload wrapped in base64 (fields: `iv`, `value`, `mac`)
- Compatible with Laravel's `Crypt::encryptString` / `decryptString`

## Testing

```bash
go test ./...
```

## License

MIT
