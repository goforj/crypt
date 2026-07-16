<p align="center">
  <img src="./docs/images/logo.png?v=2" width="300" alt="crypt logo">
</p>

<p align="center">
    Authenticated AES-128/256 CBC for Go, with explicit interoperability and key rotation.
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

**crypt** provides authenticated AES-CBC encryption for Go services and graceful key rotation through **APP_PREVIOUS_KEYS**. Existing APIs retain the package's original wire format; interoperability writes are an explicit opt-in.

- AES-128 / AES-256 CBC encryption
- Authenticated encryption (AES-CBC + HMAC)
- Explicit alternate-envelope interoperability
- Automatic reads of both supported CBC envelopes
- Transparent key rotation via `APP_PREVIOUS_KEYS`
- Zero dependencies (stdlib only)
- Instanced and global usage styles
- Stable error identities for invalid keys, malformed payloads, and authentication failures

## Why crypt?

**crypt** exists to solve one problem well: encrypting small application payloads with safe defaults and painless key rotation.

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

	// Encrypt preserves crypt's original wire format.
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

For the alternate interoperability envelope, make the write mode explicit:

```go
ciphertext, err := c.EncryptForInterop("secret")
```

`c.Decrypt` automatically reads both formats.

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

	ciphertext, _ := crypt.EncryptForInterop("secret")
	plaintext, _ := crypt.Decrypt(ciphertext)

	fmt.Println(plaintext) // "secret"
}
```

## Key format & rotation

`crypt` uses a base64-prefixed application-key syntax and supports graceful decryption during rotation.

* **`APP_KEY`** must be prefixed with `base64:` and decode to either **16 bytes (AES-128)** or **32 bytes (AES-256)**.
* **`APP_PREVIOUS_KEYS`** is optional and may contain a comma-separated list of older keys in the same format.
* During decryption, the current key is tried first, followed by any previous keys.
* Encryption **always** uses the current `APP_KEY`; previous keys are never used for encryption.

### Example

```bash
export APP_KEY="base64:J63qRTDLub5NuZvP+kb8YIorGS6qFYHKVo6u7179stY="
export APP_PREVIOUS_KEYS="base64:2nLsGFGzyoae2ax3EF2Lyq/hH6QghBGLIq5uL+Gp8/w="
```

## Wire-format compatibility

| Operation | crypt original format | Laravel 12 CBC `encryptString` |
|---|---:|---:|
| `Encrypt` / `(*Cipher).Encrypt` writes | Yes | No |
| `EncryptForInterop` / `(*Cipher).EncryptForInterop` writes | No | Yes |
| `Decrypt` / `(*Cipher).Decrypt` reads | Yes | Yes |

The interoperability writer follows the official CBC envelope: outer-base64 JSON containing
`iv`, `value`, lowercase hexadecimal `mac`, and an explicit empty `tag`. It signs
the base64 IV and ciphertext strings, matching Laravel's
[`Encrypter`](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Encryption/Encrypter.php).
A 16-byte key selects AES-128-CBC and a 32-byte key selects AES-256-CBC.

Compatibility is intentionally limited to Laravel's string API. `crypt` does not
produce or consume PHP-serialized values from Laravel's generic `encrypt` method,
and it does not support Laravel's GCM ciphers. See Laravel's
[encryption documentation](https://laravel.com/docs/12.x/encryption) for the upstream model.

## Migrating writers safely

Existing `Encrypt` calls and ciphertext remain unchanged. To adopt interoperability writes:

1. Deploy this version everywhere values may be decrypted. Its readers accept both formats.
2. Change only the intended writers to `EncryptForInterop`.
3. Re-encrypt stored legacy values gradually if an external consumer must read them.
4. Keep required old keys in `APP_PREVIOUS_KEYS` until all ciphertext using them has expired or migrated.

No flag silently changes existing writers. `EncryptedPayload` also retains its original
three-field shape for source compatibility with keyed and unkeyed composite literals.

## Security and error handling

- A fresh cryptographic IV is generated for every write. Payloads are authenticated before CBC decryption or padding inspection.
- `ErrInvalidKey`, `ErrInvalidPayload`, and `ErrAuthentication` support `errors.Is`; error text never includes key, plaintext, or ciphertext values.
- The library deliberately imposes no arbitrary payload-size cap. Encryption buffers the payload in memory, so callers should apply limits appropriate to their trust boundary.
- Treat `APP_KEY` and `APP_PREVIOUS_KEYS` as secrets. Do not log them, embed them in source, or remove a previous key while live ciphertext still depends on it.

## Mutating `.env` files

> **Warning:** `GenerateKeyToEnv` is a destructive reset. It replaces `APP_KEY` and
> removes every active `APP_PREVIOUS_KEYS` assignment. Existing ciphertext may become
> permanently unreadable. Use `RotateKeyInEnv` when retaining decryption history.

Both helpers preserve comments, unrelated formatting, quote style, CRLF/LF endings,
and an existing file's permission mode. New files are created with mode `0600`.
Audit older files and restrict them to `0600` when deployment requirements allow;
the library does not silently change an existing explicit mode. Replacement files
remain `0600` while secret bytes are prepared, then receive the preserved final mode
immediately before the synced rename.

Writes use a synced same-directory temporary file and atomic rename. Final-component
symlinks are rejected, and same-path mutations are serialized within one process.
Unrelated processes must coordinate their read-modify-write operations separately.
Atomic replacement creates an inode owned by the writing process, so run these helpers
under the account that should own the resulting file. If rename commits but directory
sync reports a durability error, the helper returns both the installed key and the error.

Benchmarks for both formats are available with `go test -bench=. -benchmem`.

## Runnable examples

Runnable examples for the documented workflows live under [`./examples`](./examples).

Examples are generated directly from function doc comments, and the same snippets power the README and GoDoc examples.

An automated test builds every example so the docs stay valid as the API evolves.

<!-- api:embed:start -->

## <a id="api-index"></a>API Index

Global = package-level functions (env-based convenience).
Instanced = methods on `*crypt.Cipher` with injected keys.

| Group | Namespace | Functions |
|------:|-----------|-----------|
| **Encryption** | Global | [Decrypt](#decrypt) · [Encrypt](#encrypt) · [EncryptForInterop](#encryptforinterop) |
| **Encryption** | Instanced | [Cipher.Decrypt](#cipher-decrypt) · [Cipher.Encrypt](#cipher-encrypt) · [Cipher.EncryptForInterop](#cipher-encryptforinterop) |
| **Key management** | Global | [GenerateAppKey](#generateappkey) · [GenerateKeyToEnv](#generatekeytoenv) · [GetAppKey](#getappkey) · [GetPreviousAppKeys](#getpreviousappkeys) · [New](#new) · [NewFromEnv](#newfromenv) · [ReadAppKey](#readappkey) · [RotateKeyInEnv](#rotatekeyinenv) |


## Encryption

### Global

#### <a id="decrypt"></a>Decrypt

Decrypt decrypts either supported payload format using APP_KEY and APP_PREVIOUS_KEYS.

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

Encrypt encrypts plaintext with APP_KEY in crypt's original payload format.
Existing ciphertext writers retain their historical wire contract.

```go
appKey, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", appKey)
ciphertext, err := crypt.Encrypt("secret")
godump.Dump(err == nil, ciphertext != "")
// #bool true
// #bool true
```

#### <a id="encryptforinterop"></a>EncryptForInterop

EncryptForInterop encrypts plaintext with APP_KEY using the interoperability CBC envelope.
The envelope signs the base64 IV and ciphertext, encodes the MAC as lowercase hex, and includes an empty tag.
This explicit opt-in avoids silently changing the existing Encrypt wire format.

```go
appKey, _ := crypt.GenerateAppKey()
_ = os.Setenv("APP_KEY", appKey)
ciphertext, err := crypt.EncryptForInterop("secret")
godump.Dump(err == nil, ciphertext != "")
// #bool true
// #bool true
```

### Instanced

#### <a id="cipher-decrypt"></a>Cipher.Decrypt

Decrypt decrypts either supported CBC envelope.
It authenticates with the current key first, followed by configured previous keys.

#### <a id="cipher-encrypt"></a>Cipher.Encrypt

Encrypt encrypts plaintext with the Cipher's current key in crypt's original format.
Existing callers keep the same wire format; use EncryptForInterop when an external consumer requires the alternate envelope.

#### <a id="cipher-encryptforinterop"></a>Cipher.EncryptForInterop

EncryptForInterop encrypts plaintext with the Cipher's current key using the interoperability CBC envelope.
The envelope signs the base64 IV and ciphertext, encodes the MAC as lowercase hex, and includes an empty tag.
This explicit opt-in leaves Encrypt's established wire format unchanged.

```go
key := make([]byte, 32)
c, _ := crypt.New(key)
ciphertext, err := c.EncryptForInterop("secret")
godump.Dump(err == nil, ciphertext != "")
// #bool true
// #bool true
```

## Key management

### Global

#### <a id="generateappkey"></a>GenerateAppKey

GenerateAppKey generates a random AES-256 key using the base64-prefixed APP_KEY syntax.

```go
key, _ := crypt.GenerateAppKey()
godump.Dump(key)
// #string "base64:..."
```

#### <a id="generatekeytoenv"></a>GenerateKeyToEnv

GenerateKeyToEnv creates a new APP_KEY and destructively clears APP_PREVIOUS_KEYS.

This operation is a reset, not a graceful rotation. Existing ciphertext that
requires a cleared previous key becomes unreadable; use RotateKeyInEnv to retain
decryption history. New files use mode 0600, while existing file permissions are
preserved. Final-component symlinks are rejected. If the atomic rename commits but
syncing its directory fails, the installed key is returned together with the error.

```go
dir, _ := os.MkdirTemp("", "crypt-reset-*")
defer os.RemoveAll(dir)
envPath := filepath.Join(dir, ".env")
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

ReadAppKey parses a base64-prefixed AES-128 or AES-256 application key.

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

RotateKeyInEnv writes a new APP_KEY and prepends the old key to APP_PREVIOUS_KEYS.

Same-path calls are serialized within this process so concurrent rotations retain
every key. Atomic replacement prevents partial files, but unrelated processes must
still coordinate their read-modify-write operations with the caller. If the atomic
rename commits but syncing its directory fails, the installed key is returned with
the error so callers do not lose track of active key material.

```go
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
```
<!-- api:embed:end -->
