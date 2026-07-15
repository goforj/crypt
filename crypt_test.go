package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

const (
	fixtureIVHex = "101112131415161718191a1b1c1d1e1f"
	key128Hex    = "000102030405060708090a0b0c0d0e0f"
	key256Hex    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

// laravelFixture records independently derived Laravel 12 CBC encryptString vectors.
type laravelFixture struct {
	name       string
	keyHex     string
	plaintext  string
	ciphertext string
}

// legacyFixture freezes ciphertext written by crypt's original payload contract.
type legacyFixture struct {
	name       string
	keyHex     string
	plaintext  string
	ciphertext string
}

var laravelFixtures = []laravelFixture{
	{
		name:       "aes128_empty",
		keyHex:     key128Hex,
		plaintext:  "",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiQ3BRTHRVRnU4RVh4dzVSWXhsUHFXZz09IiwibWFjIjoiZjkxOGEyNmRiY2U5YmM5Nzk1OTA2MTkyMzE4ZThjODEwMDhkZDJkYzMwOGY4Y2QyYmNlZjg3ODU5ZGY1NjZjYiIsInRhZyI6IiJ9",
	},
	{
		name:       "aes128_normal",
		keyHex:     key128Hex,
		plaintext:  "Hello, Laravel!",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiZHN6Z2MrY1VSVmNWdFIwUkV6cXk4dz09IiwibWFjIjoiMjVkMmVlYjNjN2RiODNhNGFkNTQzMmEzNjU2YzFmZjRmMGNlZDhiZTgzYTQ1ODUwYWRkNDgyYjQ5YjRmNjE0MCIsInRhZyI6IiJ9",
	},
	{
		name:       "aes128_unicode",
		keyHex:     key128Hex,
		plaintext:  "Zażółć gęślą jaźń 🔐",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiMTFHaW5rdi9QdGYxRWFwSjB2MStnOWNMbFVYclgxSm0zMTJVZDU1UitGVT0iLCJtYWMiOiI3ZDUxMDRlNDU5NzNlZmM1MjQ4Yzk3MmVjYWViZGZhMmMyNDFlZjA0NmQwZTk4Y2Q1YTUxNTllNTQzNDRkZWZkIiwidGFnIjoiIn0=",
	},
	{
		name:       "aes256_empty",
		keyHex:     key256Hex,
		plaintext:  "",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiV200RVZ3ajdjWmJ3TGxVOUFzT21rZz09IiwibWFjIjoiYjI0OTk0OTMyMWI3ODcwM2NhMWNiZmY4OGY0MWQ5M2U5ZjdmZTE0Mjg0YmU0NTU3MWNkMzdjYmQ5MjE1ZWRkNyIsInRhZyI6IiJ9",
	},
	{
		name:       "aes256_normal",
		keyHex:     key256Hex,
		plaintext:  "Hello, Laravel!",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiQzFSSG8wNW83V1FCYXRveWZ6bTB4QT09IiwibWFjIjoiOWE5NDllNmM5ZGRkZDI1MzkzYzFiODJiZjU1OTJkNTM4ZmJlNjEyZjQxYTNhNTExZTJiMDIxYTYyZjUyY2M1MCIsInRhZyI6IiJ9",
	},
	{
		name:       "aes256_unicode",
		keyHex:     key256Hex,
		plaintext:  "Zażółć gęślą jaźń 🔐",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiaURjSFBVT0l5SFdTWHJ3UDQ2ZGpibnE5VTNLWmZqeHZwUkJFR3E3eURMQT0iLCJtYWMiOiJhMmRkY2RmZmRkNDFjOTUyMzI1NDJlNGJmZjVkYTA4NjA1OWZhMDdlMGRmYWNmNzJhOThiMjM2MTU4MzZlMzZjIiwidGFnIjoiIn0=",
	},
}

var legacyFixtures = []legacyFixture{
	{
		name:       "aes128_normal",
		keyHex:     key128Hex,
		plaintext:  "Hello, legacy!",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiN0RKUTRGMlgyZVdzNVJYWEwzc2ZkQT09IiwibWFjIjoiS1JGS1VVdUhoZ3g0d1lQMlloeWpCaWxRWjE4NXpkblQxT1JhdG1zMGFXMD0ifQ==",
	},
	{
		name:       "aes256_unicode",
		keyHex:     key256Hex,
		plaintext:  "Zażółć gęślą jaźń 🔐",
		ciphertext: "eyJpdiI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHc9PSIsInZhbHVlIjoiaURjSFBVT0l5SFdTWHJ3UDQ2ZGpibnE5VTNLWmZqeHZwUkJFR3E3eURMQT0iLCJtYWMiOiJES2tmbmZ3bC9BMnhWek1GMmd6YjJkQUZpWkt5c3pmSXNNbHRHNkdMVEtBPSJ9",
	},
}

// failingReader makes entropy failure paths deterministic without replacing crypto/rand globals.
type failingReader struct{}

// Read always fails before returning entropy.
func (failingReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// fixedKey decodes a test key and fails at the call site on fixture mistakes.
func fixedKey(t *testing.T, value string) []byte {
	t.Helper()
	key, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode key fixture: %v", err)
	}
	return key
}

// fixtureIV decodes the fixed IV used by both independent fixture sets.
func fixtureIV(t *testing.T) []byte {
	t.Helper()
	iv, err := hex.DecodeString(fixtureIVHex)
	if err != nil {
		t.Fatalf("decode IV fixture: %v", err)
	}
	return iv
}

// generatedKeyPair returns both representations used by env and instance APIs.
func generatedKeyPair(t *testing.T) ([]byte, string) {
	t.Helper()
	encoded, err := GenerateAppKey()
	if err != nil {
		t.Fatalf("GenerateAppKey: %v", err)
	}
	key, err := ReadAppKey(encoded)
	if err != nil {
		t.Fatalf("ReadAppKey: %v", err)
	}
	return key, encoded
}

// encodeTestEnvelope builds malformed and tampered envelopes without depending on production structs.
func encodeTestEnvelope(t *testing.T, envelope any) string {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal test envelope: %v", err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// TestGenerateAppKeyAndReadAppKey guards supported key generation and parsing against regressions.
func TestGenerateAppKeyAndReadAppKey(t *testing.T) {
	key, encoded := generatedKeyPair(t)
	if len(key) != 32 {
		t.Fatalf("GenerateAppKey decoded to %d bytes", len(key))
	}
	if !strings.HasPrefix(encoded, "base64:") {
		t.Fatalf("GenerateAppKey returned unexpected syntax")
	}

	key128 := fixedKey(t, key128Hex)
	parsed, err := ReadAppKey("base64:" + base64.StdEncoding.EncodeToString(key128))
	if err != nil || !bytes.Equal(parsed, key128) {
		t.Fatalf("ReadAppKey AES-128 = %x, %v", parsed, err)
	}
	nonCanonical := "base64:AAAAAAAAAAAAAAAAAAAAAB=="
	parsed, err = ReadAppKey(nonCanonical)
	if err != nil || !bytes.Equal(parsed, make([]byte, 16)) {
		t.Fatalf("ReadAppKey historical base64 tolerance = %x, %v", parsed, err)
	}
}

// TestReadAppKeyRejectsInvalidInputWithoutLeakingIt guards invalid-key errors against secret disclosure.
func TestReadAppKeyRejectsInvalidInputWithoutLeakingIt(t *testing.T) {
	secret := "DO-NOT-LEAK-this-secret"
	tests := []string{
		secret,
		"base64:" + secret,
		"base64:" + base64.StdEncoding.EncodeToString(make([]byte, 24)),
	}
	for _, input := range tests {
		_, err := ReadAppKey(input)
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("ReadAppKey(%q) error = %v", input, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("ReadAppKey error leaked key input: %v", err)
		}
	}
}

// TestGenerateAppKeyEntropyFailure guards propagation of cryptographic entropy failures.
func TestGenerateAppKeyEntropyFailure(t *testing.T) {
	if _, err := generateAppKey(failingReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("generateAppKey error = %v", err)
	}
}

// TestEnvironmentKeyReaders guards current and previous environment key parsing against regressions.
func TestEnvironmentKeyReaders(t *testing.T) {
	first, firstEncoded := generatedKeyPair(t)
	second, secondEncoded := generatedKeyPair(t)
	t.Setenv("APP_KEY", firstEncoded)
	t.Setenv("APP_PREVIOUS_KEYS", "  "+firstEncoded+" , , "+secondEncoded+", ")

	current, err := GetAppKey()
	if err != nil || !bytes.Equal(current, first) {
		t.Fatalf("GetAppKey = %x, %v", current, err)
	}
	previous, err := GetPreviousAppKeys()
	if err != nil {
		t.Fatalf("GetPreviousAppKeys: %v", err)
	}
	if len(previous) != 2 || !bytes.Equal(previous[0], first) || !bytes.Equal(previous[1], second) {
		t.Fatalf("GetPreviousAppKeys returned unexpected keys")
	}
}

// TestEnvironmentKeyReaderErrors guards missing and malformed environment key error identities.
func TestEnvironmentKeyReaderErrors(t *testing.T) {
	t.Setenv("APP_KEY", "")
	if _, err := GetAppKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("GetAppKey error = %v", err)
	}
	t.Setenv("APP_PREVIOUS_KEYS", "bad-key")
	if _, err := GetPreviousAppKeys(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("GetPreviousAppKeys error = %v", err)
	}
	t.Setenv("APP_PREVIOUS_KEYS", "")
	keys, err := GetPreviousAppKeys()
	if err != nil || keys != nil {
		t.Fatalf("empty GetPreviousAppKeys = %#v, %v", keys, err)
	}
}

// TestGlobalAPIsPropagateEnvironmentErrors guards package-level helpers against swallowed configuration failures.
func TestGlobalAPIsPropagateEnvironmentErrors(t *testing.T) {
	t.Setenv("APP_KEY", "")
	t.Setenv("APP_PREVIOUS_KEYS", "")
	for name, call := range map[string]func() error{
		"new": func() error {
			_, err := NewFromEnv()
			return err
		},
		"encrypt": func() error {
			_, err := Encrypt("secret")
			return err
		},
		"encrypt_laravel": func() error {
			_, err := EncryptLaravel("secret")
			return err
		},
		"decrypt": func() error {
			_, err := Decrypt("ciphertext")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("global API error = %v", err)
			}
		})
	}

	t.Setenv("APP_KEY", "base64:"+base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("APP_PREVIOUS_KEYS", "invalid")
	if _, err := NewFromEnv(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewFromEnv previous-key error = %v", err)
	}
}

// TestNewValidatesAndCopiesKeys guards key validation and caller-slice ownership boundaries.
func TestNewValidatesAndCopiesKeys(t *testing.T) {
	current := fixedKey(t, key256Hex)
	previous := fixedKey(t, key128Hex)
	cipher, err := New(current, previous)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	current[0] ^= 0xff
	previous[0] ^= 0xff
	if bytes.Equal(cipher.key, current) || bytes.Equal(cipher.previousKeys[0], previous) {
		t.Fatal("New retained caller-owned key storage")
	}

	if _, err := New(make([]byte, 15)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("New invalid current key error = %v", err)
	}
	if _, err := New(make([]byte, 16), make([]byte, 31)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("New invalid previous key error = %v", err)
	}
}

// TestNewFromEnv guards construction from current and previous environment keys.
func TestNewFromEnv(t *testing.T) {
	_, current := generatedKeyPair(t)
	_, previous := generatedKeyPair(t)
	t.Setenv("APP_KEY", current)
	t.Setenv("APP_PREVIOUS_KEYS", previous)
	cipher, err := NewFromEnv()
	if err != nil || cipher == nil || len(cipher.previousKeys) != 1 {
		t.Fatalf("NewFromEnv = %#v, %v", cipher, err)
	}
}

// TestCipherNilReceiver guards nil receiver methods against panics.
func TestCipherNilReceiver(t *testing.T) {
	var cipher *Cipher
	if _, err := cipher.Encrypt("x"); !errors.Is(err, errNilCipher) {
		t.Fatalf("Cipher.Encrypt error = %v", err)
	}
	if _, err := cipher.EncryptLaravel("x"); !errors.Is(err, errNilCipher) {
		t.Fatalf("Cipher.EncryptLaravel error = %v", err)
	}
	if _, err := cipher.Decrypt("x"); !errors.Is(err, errNilCipher) {
		t.Fatalf("Cipher.Decrypt error = %v", err)
	}
}

// TestCipherZeroValueReturnsInvalidKey guards deterministic errors for unconstructed Cipher values.
func TestCipherZeroValueReturnsInvalidKey(t *testing.T) {
	var cipher Cipher
	for name, call := range map[string]func() error{
		"encrypt": func() error {
			_, err := cipher.Encrypt("secret")
			return err
		},
		"encrypt_laravel": func() error {
			_, err := cipher.EncryptLaravel("secret")
			return err
		},
		"decrypt": func() error {
			_, err := cipher.Decrypt("malformed")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("zero-value Cipher error = %v", err)
			}
		})
	}

	cipher.key = make([]byte, 16)
	cipher.previousKeys = [][]byte{nil}
	if _, err := cipher.Decrypt(legacyFixtures[0].ciphertext); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("invalid previous key error = %v", err)
	}
}

// TestLegacyFixturesRemainExact guards the original ciphertext wire format against drift.
func TestLegacyFixturesRemainExact(t *testing.T) {
	for _, fixture := range legacyFixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			key := fixedKey(t, fixture.keyHex)
			got, err := encryptWithKeyAndReader(key, fixture.plaintext, payloadFormatLegacy, bytes.NewReader(fixtureIV(t)))
			if err != nil {
				t.Fatalf("encrypt legacy fixture: %v", err)
			}
			if got != fixture.ciphertext {
				t.Fatalf("legacy ciphertext drifted\ngot:  %s\nwant: %s", got, fixture.ciphertext)
			}
			plaintext, err := decryptWithKey(key, fixture.ciphertext)
			if err != nil || plaintext != fixture.plaintext {
				t.Fatalf("decrypt legacy fixture = %q, %v", plaintext, err)
			}
		})
	}
}

// TestLegacyReadPreservesHistoricalBase64WhitespaceTolerance guards backward-compatible base64 decoding.
func TestLegacyReadPreservesHistoricalBase64WhitespaceTolerance(t *testing.T) {
	key := fixedKey(t, key128Hex)
	raw, err := base64.StdEncoding.DecodeString(legacyFixtures[0].ciphertext)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	var payload EncryptedPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	payload.IV = payload.IV[:4] + "\r\n" + payload.IV[4:]
	payload.Value = payload.Value[:4] + "\n" + payload.Value[4:]
	encoded := encodeTestEnvelope(t, payload)
	encoded = encoded[:8] + "\n" + encoded[8:]
	plaintext, err := decryptWithKey(key, encoded)
	if err != nil || plaintext != legacyFixtures[0].plaintext {
		t.Fatalf("historically tolerated payload = %q, %v", plaintext, err)
	}
}

// TestLaravelFixturesMatchExactWireContract guards Laravel CBC interoperability against wire drift.
func TestLaravelFixturesMatchExactWireContract(t *testing.T) {
	for _, fixture := range laravelFixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			key := fixedKey(t, fixture.keyHex)
			got, err := encryptWithKeyAndReader(key, fixture.plaintext, payloadFormatLaravel, bytes.NewReader(fixtureIV(t)))
			if err != nil {
				t.Fatalf("encrypt Laravel fixture: %v", err)
			}
			if got != fixture.ciphertext {
				t.Fatalf("Laravel ciphertext mismatch\ngot:  %s\nwant: %s", got, fixture.ciphertext)
			}
			plaintext, err := decryptWithKey(key, fixture.ciphertext)
			if err != nil || plaintext != fixture.plaintext {
				t.Fatalf("decrypt Laravel fixture = %q, %v", plaintext, err)
			}
		})
	}
}

// TestPayloadStructShapeAndEmissionFields guards source compatibility and format-specific envelope fields.
func TestPayloadStructShapeAndEmissionFields(t *testing.T) {
	_ = EncryptedPayload{"iv", "value", "mac"}
	key := fixedKey(t, key256Hex)

	legacy, err := encryptWithKeyAndReader(key, "secret", payloadFormatLegacy, bytes.NewReader(fixtureIV(t)))
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}
	laravel, err := encryptWithKeyAndReader(key, "secret", payloadFormatLaravel, bytes.NewReader(fixtureIV(t)))
	if err != nil {
		t.Fatalf("Laravel encrypt: %v", err)
	}

	for name, encoded := range map[string]string{"legacy": legacy, "laravel": laravel} {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode %s payload: %v", name, err)
		}
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("decode %s JSON: %v", name, err)
		}
		_, hasTag := fields["tag"]
		if name == "legacy" && hasTag {
			t.Fatal("legacy payload unexpectedly gained tag field")
		}
		if name == "laravel" && (!hasTag || fields["tag"] != "") {
			t.Fatalf("Laravel tag = %#v", fields["tag"])
		}
	}
}

// TestPublicEncryptionAPIsAndAutomaticReads guards both writers and automatic dual-format reads.
func TestPublicEncryptionAPIsAndAutomaticReads(t *testing.T) {
	key, encodedKey := generatedKeyPair(t)
	t.Setenv("APP_KEY", encodedKey)
	t.Setenv("APP_PREVIOUS_KEYS", "")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	writers := []struct {
		name  string
		write func(string) (string, error)
	}{
		{name: "global_legacy", write: Encrypt},
		{name: "global_laravel", write: EncryptLaravel},
		{name: "instance_legacy", write: cipher.Encrypt},
		{name: "instance_laravel", write: cipher.EncryptLaravel},
	}
	for _, writer := range writers {
		writer := writer
		t.Run(writer.name, func(t *testing.T) {
			encoded, err := writer.write("Go + Laravel 🔐")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := cipher.Decrypt(encoded)
			if err != nil || got != "Go + Laravel 🔐" {
				t.Fatalf("instance decrypt = %q, %v", got, err)
			}
			got, err = Decrypt(encoded)
			if err != nil || got != "Go + Laravel 🔐" {
				t.Fatalf("global decrypt = %q, %v", got, err)
			}
		})
	}
}

// TestDecryptUsesPreviousKeysForBothFormats guards graceful rotation across both wire formats.
func TestDecryptUsesPreviousKeysForBothFormats(t *testing.T) {
	current := bytes.Repeat([]byte{0xa5}, 32)
	previous128 := fixedKey(t, key128Hex)
	previous256 := fixedKey(t, key256Hex)
	cipher, err := New(current, previous128, previous256)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, fixture := range []struct {
		ciphertext string
		plaintext  string
	}{
		{ciphertext: legacyFixtures[0].ciphertext, plaintext: legacyFixtures[0].plaintext},
		{ciphertext: laravelFixtures[5].ciphertext, plaintext: laravelFixtures[5].plaintext},
	} {
		got, err := cipher.Decrypt(fixture.ciphertext)
		if err != nil || got != fixture.plaintext {
			t.Fatalf("previous-key decrypt = %q, %v", got, err)
		}
	}
}

// TestDecryptWrongKeyReturnsAuthenticationSentinel guards the stable all-keys-failed error identity.
func TestDecryptWrongKeyReturnsAuthenticationSentinel(t *testing.T) {
	cipher, err := New(bytes.Repeat([]byte{0xff}, 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, encoded := range []string{legacyFixtures[0].ciphertext, laravelFixtures[4].ciphertext} {
		_, err := cipher.Decrypt(encoded)
		if err != ErrAuthentication {
			t.Fatalf("wrong-key error = %v, want exact ErrAuthentication", err)
		}
	}
}

// TestDecryptTamperingReturnsAuthenticationSentinel guards authenticated fields against modification.
func TestDecryptTamperingReturnsAuthenticationSentinel(t *testing.T) {
	key := fixedKey(t, key256Hex)
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(laravelFixtures[4].ciphertext)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}

	tests := map[string]func(map[string]any){
		"iv": func(value map[string]any) {
			iv, _ := base64.StdEncoding.DecodeString(value["iv"].(string))
			iv[0] ^= 1
			value["iv"] = base64.StdEncoding.EncodeToString(iv)
		},
		"value": func(value map[string]any) {
			ciphertext, _ := base64.StdEncoding.DecodeString(value["value"].(string))
			ciphertext[0] ^= 1
			value["value"] = base64.StdEncoding.EncodeToString(ciphertext)
		},
		"mac": func(value map[string]any) {
			mac := []byte(value["mac"].(string))
			mac[0] = '0' + (mac[0]-'0'+1)%10
			value["mac"] = string(mac)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copyEnvelope := make(map[string]any, len(envelope))
			for field, value := range envelope {
				copyEnvelope[field] = value
			}
			mutate(copyEnvelope)
			if _, err := cipher.Decrypt(encodeTestEnvelope(t, copyEnvelope)); err != ErrAuthentication {
				t.Fatalf("tampered error = %v", err)
			}
		})
	}
}

// TestDecryptRejectsMalformedPayloadsWithoutPanicking guards total parsing of hostile envelopes.
func TestDecryptRejectsMalformedPayloadsWithoutPanicking(t *testing.T) {
	key := fixedKey(t, key256Hex)
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	validIV := base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize))
	validValue := base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize))
	validLegacyMAC := base64.StdEncoding.EncodeToString(make([]byte, 32))
	validLaravelMAC := strings.Repeat("a", 64)

	tests := map[string]string{
		"outer_base64":   "not base64!",
		"json":           base64.StdEncoding.EncodeToString([]byte("{")),
		"json_null":      encodeTestEnvelope(t, nil),
		"missing_iv":     encodeTestEnvelope(t, map[string]any{"value": validValue, "mac": validLegacyMAC}),
		"iv_encoding":    encodeTestEnvelope(t, map[string]any{"iv": "?", "value": validValue, "mac": validLegacyMAC}),
		"iv_length":      encodeTestEnvelope(t, map[string]any{"iv": base64.StdEncoding.EncodeToString(make([]byte, 15)), "value": validValue, "mac": validLegacyMAC}),
		"value_encoding": encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": "?", "mac": validLegacyMAC}),
		"value_empty":    encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": "", "mac": validLegacyMAC}),
		"value_partial":  encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), "mac": validLegacyMAC}),
		"mac_encoding":   encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": validValue, "mac": "?"}),
		"mac_length":     encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": validValue, "mac": base64.StdEncoding.EncodeToString(make([]byte, 31))}),
		"mac_upper_hex":  encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": validValue, "mac": strings.ToUpper(validLaravelMAC)}),
		"tag_non_string": encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": validValue, "mac": validLaravelMAC, "tag": 1}),
		"tag_non_empty":  encodeTestEnvelope(t, map[string]any{"iv": validIV, "value": validValue, "mac": validLaravelMAC, "tag": "aGVsbG8="}),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := cipher.Decrypt(encoded)
			if !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("malformed payload error = %v", err)
			}
			if strings.Contains(err.Error(), encoded) {
				t.Fatal("malformed payload error leaked ciphertext")
			}
		})
	}
}

// TestDecryptAcceptsOmittedOrNullEmptyCBCTag guards supported CBC tag representations.
func TestDecryptAcceptsOmittedOrNullEmptyCBCTag(t *testing.T) {
	key := fixedKey(t, key128Hex)
	raw, err := base64.StdEncoding.DecodeString(legacyFixtures[0].ciphertext)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	for name, tag := range map[string]any{"empty": "", "null": nil} {
		t.Run(name, func(t *testing.T) {
			envelope["tag"] = tag
			got, err := decryptWithKey(key, encodeTestEnvelope(t, envelope))
			if err != nil || got != legacyFixtures[0].plaintext {
				t.Fatalf("decrypt tag variant = %q, %v", got, err)
			}
		})
	}
}

// TestDecryptAuthenticatedInvalidPadding guards malformed authenticated plaintext against unsafe unpadding.
func TestDecryptAuthenticatedInvalidPadding(t *testing.T) {
	key := fixedKey(t, key128Hex)
	iv := fixtureIV(t)
	invalidPadded := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("AES: %v", err)
	}
	ciphertext := make([]byte, len(invalidPadded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, invalidPadded)
	payload := EncryptedPayload{
		IV:    base64.StdEncoding.EncodeToString(iv),
		Value: base64.StdEncoding.EncodeToString(ciphertext),
		MAC:   base64.StdEncoding.EncodeToString(computeHMACSHA256Parts(key, iv, ciphertext)),
	}
	_, err = decryptWithKey(key, encodeTestEnvelope(t, payload))
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("padding error = %v", err)
	}
}

// TestEncryptionInternalFailures guards internal key, entropy, and format failure paths.
func TestEncryptionInternalFailures(t *testing.T) {
	if _, err := encryptWithKeyAndReader(make([]byte, 15), "secret", payloadFormatLegacy, bytes.NewReader(fixtureIV(t))); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("invalid key error = %v", err)
	}
	if _, err := encryptWithKeyAndReader(make([]byte, 16), "secret", payloadFormatLegacy, failingReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("entropy error = %v", err)
	}
	if _, err := encryptWithKeyAndReader(make([]byte, 16), "secret", payloadFormat(99), bytes.NewReader(fixtureIV(t))); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("format error = %v", err)
	}
	if _, err := decryptWithKey(make([]byte, 17), legacyFixtures[0].ciphertext); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("decrypt invalid key error = %v", err)
	}
	if (parsedEncryptedPayload{format: payloadFormat(99)}).authenticates(make([]byte, 16)) {
		t.Fatal("unknown payload format authenticated")
	}
	if _, err := decryptAuthenticatedPayload(make([]byte, 17), parsedEncryptedPayload{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("authenticated decrypt invalid key error = %v", err)
	}
}

// TestNoArbitraryPlaintextLimit guards large valid payloads against undocumented caps.
func TestNoArbitraryPlaintextLimit(t *testing.T) {
	key := fixedKey(t, key256Hex)
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	plaintext := strings.Repeat("0123456789abcdef", 1<<16)
	encoded, err := cipher.EncryptLaravel(plaintext)
	if err != nil {
		t.Fatalf("EncryptLaravel large payload: %v", err)
	}
	got, err := cipher.Decrypt(encoded)
	if err != nil || got != plaintext {
		t.Fatalf("large round trip length = %d, %v", len(got), err)
	}
}

// TestCipherConcurrentUse guards the immutable Cipher contract under concurrent access.
func TestCipherConcurrentUse(t *testing.T) {
	key := fixedKey(t, key256Hex)
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const workers = 16
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			encoded, err := cipher.EncryptLaravel("concurrent")
			if err != nil {
				errorsSeen <- err
				return
			}
			plaintext, err := cipher.Decrypt(encoded)
			if err != nil {
				errorsSeen <- err
				return
			}
			if plaintext != "concurrent" {
				errorsSeen <- errors.New("unexpected plaintext")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("concurrent use: %v", err)
	}
}

// TestPaddingHelpers guards valid and malformed PKCS#7 padding behavior.
func TestPaddingHelpers(t *testing.T) {
	padded := pkcs7Pad([]byte("abc"), 4)
	if !bytes.Equal(padded, []byte{'a', 'b', 'c', 1}) {
		t.Fatalf("pkcs7Pad = %v", padded)
	}
	unpadded, err := pkcs7Unpad(padded)
	if err != nil || string(unpadded) != "abc" {
		t.Fatalf("pkcs7Unpad = %q, %v", unpadded, err)
	}
	for _, value := range [][]byte{nil, {1, 2, 0}, {1, 2, 3, 2}} {
		if _, err := pkcs7Unpad(value); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("pkcs7Unpad(%v) error = %v", value, err)
		}
	}
}

// FuzzCipherDecryptNeverPanics guards ciphertext parsing against input-dependent panics.
func FuzzCipherDecryptNeverPanics(f *testing.F) {
	cipher, err := New(bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x24}, 16))
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	for _, seed := range []string{"", "not-base64", legacyFixtures[0].ciphertext, laravelFixtures[4].ciphertext} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		_, _ = cipher.Decrypt(payload)
	})
}
