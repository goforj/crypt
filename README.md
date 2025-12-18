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

## Runnable examples

Every function has a corresponding runnable example under [`./examples`](./examples).

These examples are **generated directly from the documentation blocks** of each function, ensuring the docs and code never drift. These are the same examples you see here in the README and GoDoc.

An automated test executes **every example** to verify it builds and runs successfully.

This guarantees all examples are valid, up-to-date, and remain functional as the API evolves.

<!-- api:embed:start -->

## API Index

| Group | Functions |
|------:|-----------|
| **Encryption** | [Decrypt](#decrypt) [Encrypt](#encrypt) |
| **Key management** | [GenerateAppKey](#generateappkey) [GenerateKeyToEnv](#generatekeytoenv) [GetAppKey](#getappkey) [GetPreviousAppKeys](#getpreviousappkeys) [ReadAppKey](#readappkey) [RotateKeyInEnv](#rotatekeyinenv) |


## Encryption

### <a id="decrypt"></a>Decrypt · readonly

Decrypt decrypts an encrypted payload using the APP_KEY from environment.
Falls back to APP_PREVIOUS_KEYS when the current key cannot decrypt.

_Example: decrypt using current key_

```go
keyStr, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", keyStr)
c, _ := crypt.Encrypt("secret")
p, _ := crypt.Decrypt(c)
godump.Dump(p)

// #string "secret"
```

_Example: decrypt ciphertext encrypted with a previous key_

```go
oldKeyStr, _ := crypt.GenerateAppKey()
newKeyStr, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", oldKeyStr)
oldCipher, _ := crypt.Encrypt("rotated")
_ = os.Setenv("APP_KEY", newKeyStr)
_ = os.Setenv("APP_PREVIOUS_KEYS", oldKeyStr)
plain, err := crypt.Decrypt(oldCipher)
godump.Dump(plain, err)

// #string "rotated"
// #error <nil>
```

### <a id="encrypt"></a>Encrypt · readonly

Encrypt encrypts a plaintext using the APP_KEY from environment.

```go
keyStr, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", keyStr)
ciphertext, err := crypt.Encrypt("secret")
godump.Dump(err == nil, ciphertext != "")

// #bool true
// #bool true
```

## Key management

### <a id="generateappkey"></a>GenerateAppKey · readonly

GenerateAppKey generates a random base64 app key prefixed with "base64:".

```go
key, _ := crypt.GenerateAppKey()
godump.Dump(key)

// #string "base64:..."
```

### <a id="generatekeytoenv"></a>GenerateKeyToEnv · mutates-filesystem

GenerateKeyToEnv mimics Laravel's key:generate.
It generates a new APP_KEY and writes it to the provided .env path.
Other keys are preserved; APP_KEY is replaced/added.

```go
tmp := filepath.Join(os.TempDir(), ".env")
key, err := crypt.GenerateKeyToEnv(tmp)
godump.Dump(err, key)

// #error <nil>
// #string "base64:..."
```

### <a id="getappkey"></a>GetAppKey · readonly

GetAppKey retrieves the APP_KEY from the environment and parses it.

```go
keyStr, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", keyStr)
key, err := crypt.GetAppKey()
godump.Dump(len(key), err)

// #int 32
// #error <nil>
```

### <a id="getpreviousappkeys"></a>GetPreviousAppKeys · readonly

GetPreviousAppKeys retrieves and parses APP_PREVIOUS_KEYS from the environment.
Keys are expected to be comma-delimited and prefixed with "base64:".

```go
k1, _ := crypt.GenerateAppKey()
k2, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_PREVIOUS_KEYS", k1+", "+k2)
keys, err := crypt.GetPreviousAppKeys()
godump.Dump(len(keys), err)

// #int 2
// #error <nil>
```

### <a id="readappkey"></a>ReadAppKey · readonly

ReadAppKey parses a base64 encoded app key with "base64:" prefix.
Accepts 16-byte keys (AES-128) or 32-byte keys (AES-256) after decoding.

```go
key128raw := make([]byte, 16)
_, _ = rand.Read(key128raw)
key128str := "base64:" + base64.StdEncoding.EncodeToString(key128raw)

key256str, _ := crypt.GenerateAppKey()

key128, _ := crypt.ReadAppKey(key128str)
key256, _ := crypt.ReadAppKey(key256str)
godump.Dump(len(key128), len(key256))

// #int 16
// #int 32
```

### <a id="rotatekeyinenv"></a>RotateKeyInEnv · mutates-filesystem

RotateKeyInEnv mimics Laravel's key:rotate.
It moves the current APP_KEY into APP_PREVIOUS_KEYS (prepended) and writes a new APP_KEY.

```go
tmp := filepath.Join(os.TempDir(), ".env")
oldKey, _ := crypt.GenerateAppKey()
_ = os.WriteFile(tmp, []byte("APP_KEY="+oldKey+"\n"), 0o644)
newKey, err := crypt.RotateKeyInEnv(tmp)
godump.Dump(err == nil, newKey != "")

// #bool true
// #bool true
```
<!-- api:embed:end -->
