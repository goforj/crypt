# Ciphertext fixture provenance

The vectors in `crypt_test.go` use these fixed inputs:

- IV: `101112131415161718191a1b1c1d1e1f`
- AES-128 key: `000102030405060708090a0b0c0d0e0f`
- AES-256 key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`

The hex-MAC vectors were derived independently from the Go implementation
with `OpenSSL 3.0.13 30 Jan 2024`. The initial set was generated on 2026-07-15;
the neutral-text vectors were regenerated on 2026-07-16. PHP and the Laravel
runtime were not available in the validation environment. For each plaintext and
key size, the derivation used this shell recipe (with `cipher_name`, `key_hex`,
and `plaintext` set to the vector's values):

```sh
iv_hex=101112131415161718191a1b1c1d1e1f
iv_b64=$(printf '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' | openssl base64 -A)
value_b64=$(printf '%s' "$plaintext" | openssl enc "-$cipher_name" -K "$key_hex" -iv "$iv_hex" -base64 -A)
mac=$(printf '%s%s' "$iv_b64" "$value_b64" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" -r | awk '{print $1}')
printf '{"iv":"%s","value":"%s","mac":"%s","tag":""}' "$iv_b64" "$value_b64" "$mac" | openssl base64 -A
```

The steps are:

1. `openssl enc -aes-128-cbc` or `-aes-256-cbc` produced PKCS#7-padded CBC
   ciphertext with the fixed key and IV, emitted as one-line base64.
2. `openssl dgst -sha256 -mac HMAC` signed the concatenated base64 IV and base64
   ciphertext strings and emitted lowercase hexadecimal.
3. The ordered JSON object `{"iv":...,"value":...,"mac":...,"tag":""}` was
   base64 encoded.

That derivation follows Laravel 12's `Illuminate\Encryption\Encrypter::encrypt`
and `encryptString` source contract:

<https://github.com/laravel/framework/blob/12.x/src/Illuminate/Encryption/Encrypter.php>

The legacy vectors use the same independent OpenSSL CBC output, but compute the
MAC with the following raw-byte pipeline, encode it as base64, and omit `tag`:

```sh
{ printf '%s' "$iv_raw"; printf '%s' "$value_b64" | openssl base64 -d -A; } |
  openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" -binary |
  openssl base64 -A
```

They freeze the wire format emitted by this package before `Encrypt` switched to
the hex-MAC envelope.
