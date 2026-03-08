<p align="center">
  <img src="./docs/images/logo.png?v=2" width="300" alt="crypt logo">
</p>

<p align="center">
    Symmetric encryption for Go - AES-128/256 CBC with HMAC, key rotation, and portable payloads.
</p>

<p align="center">
    <a href="https://pkg.go.dev/github.com/goforj/crypt"><img src="https://pkg.go.dev/badge/github.com/goforj/crypt.svg" alt="Go Reference"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://github.com/goforj/crypt/actions"><img src="https://github.com/goforj/crypt/actions/workflows/test.yml/badge.svg" alt="Go Test"></a>
    <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.24+-blue?logo=go" alt="Go version"></a>
    <img src="https://img.shields.io/github/v/tag/goforj/crypt?label=version&sort=semver" alt="Latest tag">
    <a href="https://codecov.io/gh/goforj/crypt" ><img src="https://codecov.io/github/goforj/crypt/graph/badge.svg?token=Z8NM86Q50C"/></a>
    <a href="https://goreportcard.com/report/github.com/goforj/crypt"><img src="https://goreportcard.com/badge/github.com/goforj/crypt" alt="Go Report Card"></a>
</p>

## Install

```bash
go get github.com/goforj/crypt
```

# Features

**crypt** provides symmetric encryption for Go services with authenticated payloads (AES-CBC + HMAC) and key rotation via **APP_PREVIOUS_KEYS**. It also supports Laravel/PHP-compatible payloads for interoperability.

- AES-128 / AES-256 encryption (Laravel/PHP-compatible payload format)
- Authenticated encryption (AES-CBC + HMAC)
- Transparent key rotation via `APP_PREVIOUS_KEYS`
- Zero dependencies (stdlib only)
- Deterministic, testable API
- Instanced and global usage styles
- Safe defaults with explicit failure modes

## Why crypt?

`crypt` exists to solve one problem well: encrypting small application payloads with safe defaults and painless key rotation.

It is not a general-purpose cryptography library.

It is a focused, application-layer utility designed to be boring, predictable, and interoperable.

## Quickstart

### Instanced (recommended)

```go
package main

import (
	"fmt"

	"github.com/goforj/crypt"
)

func main() {
	appKey := "base64:..." // 16-byte (AES-128) or 32-byte (AES-256) key after decoding.
	key, err := crypt.ReadAppKey(appKey)
	if err != nil {
		panic(err)
	}

	c, err := crypt.New(key)
	if err != nil {
		panic(err)
	}

	ciphertext, err := c.Encrypt("secret")
	if err != nil {
		panic(err)
	}

	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext) // "secret"
}
```

### Global (env-based convenience)

```go
package main

import (
	"fmt"
	"os"

	"github.com/goforj/crypt"
)

func main() {
	_ = os.Setenv("APP_KEY", "base64:...")

	ciphertext, _ := crypt.Encrypt("secret")
	plaintext, _ := crypt.Decrypt(ciphertext)

	fmt.Println(plaintext) // "secret"
}
```

## Key format & rotation

`crypt` uses a base64-prefixed key format and supports key rotation. This matches Laravel/PHP conventions when interoperability is needed.

* **`APP_KEY`** must be prefixed with `base64:` and decode to either **16 bytes (AES-128)** or **32 bytes (AES-256)**.
* **`APP_PREVIOUS_KEYS`** is optional and may contain a comma-separated list of older keys in the same format.
* During decryption, the current key is tried first, followed by any previous keys.
* Encryption **always** uses the current `APP_KEY`; previous keys are never used for encryption.

### Example

```bash
export APP_KEY="base64:J63qRTDLub5NuZvP+kb8YIorGS6qFYHKVo6u7179stY="
export APP_PREVIOUS_KEYS="base64:2nLsGFGzyoae2ax3EF2Lyq/hH6QghBGLIq5uL+Gp8/w="
```

## Runnable examples

Every function has a corresponding runnable example under [`./examples`](./examples).

Examples are generated directly from function doc comments, and the same snippets power the README and GoDoc examples.

An automated test builds every example so the docs stay valid as the API evolves.

<!-- api:embed:start -->

## <a id="api-index"></a>API Index

Global = package-level functions (env-based convenience).
Instanced = methods on `*crypt.Cipher` with injected keys.

| Group | Namespace | Functions |
|------:|-----------|-----------|
| **Encryption** | Global | [Decrypt](#decrypt) [Encrypt](#encrypt) |
| **Encryption** | Instanced | [Cipher.Decrypt](#cipher-decrypt) [Cipher.Encrypt](#cipher-encrypt) |
| **Key management** | Global | [GenerateAppKey](#generateappkey) [GenerateKeyToEnv](#generatekeytoenv) [GetAppKey](#getappkey) [GetPreviousAppKeys](#getpreviousappkeys) [New](#new) [NewFromEnv](#newfromenv) [ReadAppKey](#readappkey) [RotateKeyInEnv](#rotatekeyinenv) |


## Encryption

### Global

#### <a id="decrypt"></a>Decrypt

Decrypt decrypts an encrypted payload using the APP_KEY from environment.
Falls back to APP_PREVIOUS_KEYS when the current key cannot decrypt.

_Example: decrypt using current key_

```go
appKey, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", appKey)
ciphertext, _ := crypt.Encrypt("secret")
plaintext, _ := crypt.Decrypt(ciphertext)
godump.Dump(plaintext)
// #string "secret"
```

_Example: decrypt ciphertext encrypted with a previous key_

```go
oldAppKey, _ := crypt.GenerateAppKey()
newAppKey, _ := crypt.GenerateAppKey()

// Encrypt with the old key first.
_ = os.Setenv("APP_KEY", oldAppKey)
rotatedCiphertext, _ := crypt.Encrypt("rotated")

// Rotate to a new current key, but keep the old key in APP_PREVIOUS_KEYS.
_ = os.Setenv("APP_KEY", newAppKey)
_ = os.Setenv("APP_PREVIOUS_KEYS", oldAppKey)
plaintext, err := crypt.Decrypt(rotatedCiphertext)
godump.Dump(plaintext, err)
// #string "rotated"
// #error <nil>
```

#### <a id="encrypt"></a>Encrypt

Encrypt encrypts a plaintext using the APP_KEY from environment.

```go
appKey, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", appKey)
ciphertext, err := crypt.Encrypt("secret")
godump.Dump(err == nil, ciphertext != "")
// #bool true
// #bool true
```

### Instanced

#### <a id="cipher-decrypt"></a>Cipher.Decrypt

Decrypt decrypts ciphertext with the current key, then any configured previous keys.

#### <a id="cipher-encrypt"></a>Cipher.Encrypt

Encrypt encrypts plaintext with the Cipher's injected current key.

## Key management

### Global

#### <a id="generateappkey"></a>GenerateAppKey

GenerateAppKey generates a random base64 app key prefixed with "base64:".

```go
key, _ := crypt.GenerateAppKey()
godump.Dump(key)
// #string "base64:..."
```

#### <a id="generatekeytoenv"></a>GenerateKeyToEnv

GenerateKeyToEnv mimics Laravel's key:generate.
It generates a new APP_KEY and writes it to the provided .env path.
Other keys are preserved; APP_KEY is replaced/added.

```go
envPath := filepath.Join(os.TempDir(), ".env")
key, err := crypt.GenerateKeyToEnv(envPath)
godump.Dump(err, key)
// #error <nil>
// #string "base64:..."
```

#### <a id="getappkey"></a>GetAppKey

GetAppKey retrieves the APP_KEY from the environment and parses it.

```go
appKey, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", appKey)
key, err := crypt.GetAppKey()
godump.Dump(len(key), err)
// #int 32
// #error <nil>
```

#### <a id="getpreviousappkeys"></a>GetPreviousAppKeys

GetPreviousAppKeys retrieves and parses APP_PREVIOUS_KEYS from the environment.
Keys are expected to be comma-delimited and prefixed with "base64:".

```go
oldKeyA, _ := crypt.GenerateAppKey()
oldKeyB, _ := crypt.GenerateAppKey()
// APP_PREVIOUS_KEYS is a comma-separated list.
_ = os.Setenv("APP_PREVIOUS_KEYS", oldKeyA+", "+oldKeyB)
keys, err := crypt.GetPreviousAppKeys()
godump.Dump(len(keys), err)
// #int 2
// #error <nil>
```

#### <a id="new"></a>New

New constructs a Cipher with an injected current key and optional previous keys.
Keys must be 16 bytes (AES-128) or 32 bytes (AES-256). Inputs are copied.

#### <a id="newfromenv"></a>NewFromEnv

NewFromEnv constructs a Cipher from APP_KEY and APP_PREVIOUS_KEYS.

#### <a id="readappkey"></a>ReadAppKey

ReadAppKey parses a base64 encoded app key with "base64:" prefix.
Accepts 16-byte keys (AES-128) or 32-byte keys (AES-256) after decoding.

```go
// Build a 16-byte (AES-128) key string manually.
raw16 := make([]byte, 16)
_, _ = rand.Read(raw16)
key16 := "base64:" + base64.StdEncoding.EncodeToString(raw16)

// Generate a 32-byte (AES-256) key string with the helper.
key32, _ := crypt.GenerateAppKey()

parsed16, _ := crypt.ReadAppKey(key16)
parsed32, _ := crypt.ReadAppKey(key32)
godump.Dump(len(parsed16), len(parsed32))
// #int 16
// #int 32
```

#### <a id="rotatekeyinenv"></a>RotateKeyInEnv

RotateKeyInEnv mimics Laravel's key:rotate.
It moves the current APP_KEY into APP_PREVIOUS_KEYS (prepended) and writes a new APP_KEY.

```go
envPath := filepath.Join(os.TempDir(), ".env")
currentKey, _ := crypt.GenerateAppKey()
// Seed a minimal .env with an existing APP_KEY.
_ = os.WriteFile(envPath, []byte("APP_KEY="+currentKey+"\n"), 0o644)
newKey, err := crypt.RotateKeyInEnv(envPath)
godump.Dump(err == nil, newKey != "")
// #bool true
// #bool true
```
<!-- api:embed:end -->
