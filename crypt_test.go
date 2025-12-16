package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func setTestAppKey(t *testing.T) {
	t.Helper()
	key, err := GenerateAppKey()
	if err != nil {
		t.Fatalf("GenerateAppKey failed: %v", err)
	}
	t.Setenv("APP_KEY", key)
}

func generateKeyPair(t *testing.T) ([]byte, string) {
	t.Helper()

	keyStr, err := GenerateAppKey()
	if err != nil {
		t.Fatalf("GenerateAppKey failed: %v", err)
	}

	key, err := ReadAppKey(keyStr)
	if err != nil {
		t.Fatalf("ReadAppKey failed: %v", err)
	}

	return key, keyStr
}

func generateKeyWithSize(t *testing.T, size int) (key []byte, keyStr string) {
	t.Helper()

	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	keyStr = "base64:" + base64.StdEncoding.EncodeToString(raw)

	var err error
	key, err = ReadAppKey(keyStr)
	if err != nil {
		t.Fatalf("ReadAppKey failed: %v", err)
	}
	return key, keyStr
}

func TestGenerateAndReadAppKey(t *testing.T) {
	setTestAppKey(t)

	key, err := GetAppKey()
	if err != nil {
		t.Fatalf("GetAppKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}
}

func TestReadAppKeySupports128And256(t *testing.T) {
	key128, key128Str := generateKeyWithSize(t, 16)
	key256, key256Str := generateKeyWithSize(t, 32)

	if len(key128) != 16 {
		t.Fatalf("Expected 16 bytes, got %d", len(key128))
	}
	if len(key256) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(key256))
	}

	parsed128, err := ReadAppKey(key128Str)
	if err != nil {
		t.Fatalf("ReadAppKey failed for 128-bit key: %v", err)
	}
	if len(parsed128) != 16 {
		t.Fatalf("Parsed key should be 16 bytes")
	}

	parsed256, err := ReadAppKey(key256Str)
	if err != nil {
		t.Fatalf("ReadAppKey failed for 256-bit key: %v", err)
	}
	if len(parsed256) != 32 {
		t.Fatalf("Parsed key should be 32 bytes")
	}

	if _, err := ReadAppKey("base64:" + base64.StdEncoding.EncodeToString(make([]byte, 24))); err == nil {
		t.Fatalf("Expected error for 24-byte key but got none")
	}
}

func TestReadAppKeyErrorsOnPrefix(t *testing.T) {
	if _, err := ReadAppKey("invalidprefix"); err == nil {
		t.Fatalf("Expected prefix error")
	}
}

func TestReadAppKeyBase64Error(t *testing.T) {
	if _, err := ReadAppKey("base64:not-valid"); err == nil {
		t.Fatalf("expected base64 decode error")
	}
}

func TestReadAppKeyInvalidKeySize(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString(make([]byte, 8))
	if _, err := ReadAppKey("base64:" + raw); err == nil {
		t.Fatalf("expected invalid size error")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	setTestAppKey(t)

	plaintext := "This is a secret message."

	encrypted, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("Encrypted result is empty")
	}

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted to equal original. Got: %s", decrypted)
	}
}

func TestDecryptTamperedPayloadFails(t *testing.T) {
	setTestAppKey(t)

	plaintext := "safe data"
	encrypted, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	jsonRaw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	var payload EncryptedPayload
	if err := json.Unmarshal(jsonRaw, &payload); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	macBytes, err := base64.StdEncoding.DecodeString(payload.MAC)
	if err != nil {
		t.Fatalf("mac decode failed: %v", err)
	}
	macBytes[0] ^= 0xFF
	payload.MAC = base64.StdEncoding.EncodeToString(macBytes)

	modifiedJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	tampered := base64.StdEncoding.EncodeToString(modifiedJSON)

	_, err = Decrypt(tampered)
	if err == nil || !strings.Contains(err.Error(), "HMAC validation failed") {
		t.Errorf("Expected HMAC validation to fail, got: %v", err)
	}
}

func TestDecryptInvalidPaddingWithValidMAC(t *testing.T) {
	key, keyStr := generateKeyPair(t)
	t.Setenv("APP_KEY", keyStr)

	ciphertext, err := encryptWithKey(key, "pad me")
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	raw, _ := base64.StdEncoding.DecodeString(ciphertext)
	var payload EncryptedPayload
	_ = json.Unmarshal(raw, &payload)

	ct, _ := base64.StdEncoding.DecodeString(payload.Value)
	ct[len(ct)-1] = 0 // corrupt padding byte but keep length

	payload.Value = base64.StdEncoding.EncodeToString(ct)
	// recompute MAC so HMAC passes
	ivBytes, _ := base64.StdEncoding.DecodeString(payload.IV)
	newMac := computeHMACSHA256(append(ivBytes, ct...), key)
	payload.MAC = base64.StdEncoding.EncodeToString(newMac)

	b, _ := json.Marshal(payload)
	enc := base64.StdEncoding.EncodeToString(b)

	if _, err := Decrypt(enc); err == nil || !strings.Contains(err.Error(), "invalid padding") {
		t.Fatalf("expected padding error, got %v", err)
	}
}

func TestDecryptBase64DecodeError(t *testing.T) {
	setTestAppKey(t)
	if _, err := Decrypt("!not-base64"); err == nil || !strings.Contains(err.Error(), "base64 decode failed") {
		t.Fatalf("expected base64 error, got %v", err)
	}
}

func TestDecryptMissingAppKey(t *testing.T) {
	t.Setenv("APP_KEY", "")
	if _, err := Decrypt("anything"); err == nil {
		t.Fatalf("expected error when APP_KEY missing")
	}
}

func TestDecryptFallsBackToPreviousKey(t *testing.T) {
	currentKey, currentKeyStr := generateKeyPair(t)
	previousKey, previousKeyStr := generateKeyPair(t)

	t.Setenv("APP_KEY", currentKeyStr)
	t.Setenv("APP_PREVIOUS_KEYS", previousKeyStr)

	oldCiphertext, err := encryptWithKey(previousKey, "rotated secret")
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	decrypted, err := Decrypt(oldCiphertext)
	if err != nil {
		t.Fatalf("Decrypt failed with previous key: %v", err)
	}
	if decrypted != "rotated secret" {
		t.Fatalf("Expected decrypted text to match, got %q", decrypted)
	}

	newCiphertext, err := Encrypt("fresh secret")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := decryptWithKey(previousKey, newCiphertext); err == nil {
		t.Fatalf("Expected decryption with previous key to fail for newly encrypted payload")
	}
	if decryptedCurrent, err := decryptWithKey(currentKey, newCiphertext); err != nil || decryptedCurrent != "fresh secret" {
		t.Fatalf("Decrypt with current key failed, got value %q and err %v", decryptedCurrent, err)
	}
}

func TestDecryptFailsWhenNoKeysMatch(t *testing.T) {
	_, currentKeyStr := generateKeyPair(t)
	wrongKey, _ := generateKeyPair(t)

	t.Setenv("APP_KEY", currentKeyStr)
	t.Setenv("APP_PREVIOUS_KEYS", "")

	ciphertext, err := encryptWithKey(wrongKey, "unrecoverable")
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	if _, err := Decrypt(ciphertext); err == nil {
		t.Fatal("Expected decrypt to fail when no keys match")
	}

	ciphertext, err = Encrypt("recoverable")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if decrypted, err := Decrypt(ciphertext); err != nil || decrypted != "recoverable" {
		t.Fatalf("Decrypt with current key failed, got %q and err %v", decrypted, err)
	}
}

func TestDecryptFailsOnInvalidJson(t *testing.T) {
	_, keyStr := generateKeyPair(t)
	t.Setenv("APP_KEY", keyStr)

	badJSON := base64.StdEncoding.EncodeToString([]byte("{"))
	if _, err := Decrypt(badJSON); err == nil || !strings.Contains(err.Error(), "json decode failed") {
		t.Fatalf("expected json decode error, got %v", err)
	}
}

func TestDecryptErrorsOnDecodeFailures(t *testing.T) {
	_, keyStr := generateKeyPair(t)
	t.Setenv("APP_KEY", keyStr)

	buildPayload := func(iv, val, mac string) string {
		p := EncryptedPayload{IV: iv, Value: val, MAC: mac}
		b, _ := json.Marshal(p)
		return base64.StdEncoding.EncodeToString(b)
	}

	// iv decode error
	if _, err := Decrypt(buildPayload("?", "dmFsdWU=", "bWFj")); err == nil || !strings.Contains(err.Error(), "iv decode failed") {
		t.Fatalf("expected iv decode failure")
	}

	// value decode error
	if _, err := Decrypt(buildPayload(base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize)), "?", "bWFj")); err == nil || !strings.Contains(err.Error(), "value decode failed") {
		t.Fatalf("expected value decode failure")
	}

	// mac decode error
	if _, err := Decrypt(buildPayload(base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize)), base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize)), "?")); err == nil || !strings.Contains(err.Error(), "mac decode failed") {
		t.Fatalf("expected mac decode failure")
	}
}

func TestDecryptErrorsOnBlockSize(t *testing.T) {
	key, keyStr := generateKeyPair(t)
	t.Setenv("APP_KEY", keyStr)

	iv := base64.StdEncoding.EncodeToString(make([]byte, aes.BlockSize))
	val := base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) // not multiple of block size
	mac := base64.StdEncoding.EncodeToString(computeHMACSHA256(append(make([]byte, aes.BlockSize), []byte{1, 2, 3}...), key))

	payload := EncryptedPayload{IV: iv, Value: val, MAC: mac}
	raw, _ := json.Marshal(payload)
	enc := base64.StdEncoding.EncodeToString(raw)

	if _, err := Decrypt(enc); err == nil || !strings.Contains(err.Error(), "multiple of the block size") {
		t.Fatalf("expected block size error, got %v", err)
	}
}

func TestEncryptFailsWithoutAppKey(t *testing.T) {
	t.Setenv("APP_KEY", "")
	if _, err := Encrypt("secret"); err == nil {
		t.Fatalf("expected error when APP_KEY missing")
	}
}

func TestGetAppKeyErrorWhenMissing(t *testing.T) {
	t.Setenv("APP_KEY", "")
	if _, err := GetAppKey(); err == nil {
		t.Fatalf("expected error when APP_KEY missing")
	}
}

func TestEncryptWithKeyInvalidSize(t *testing.T) {
	if _, err := encryptWithKey([]byte{1, 2, 3}, "data"); err == nil {
		t.Fatalf("expected invalid key size error")
	}
}

func TestEncryptWithKeyRandError(t *testing.T) {
	key, _ := generateKeyPair(t)
	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	if _, err := encryptWithKey(key, "data"); err == nil {
		t.Fatalf("expected rand failure")
	}
}

func TestDecryptFailsOnInvalidPreviousKeys(t *testing.T) {
	_, currentKeyStr := generateKeyPair(t)
	t.Setenv("APP_KEY", currentKeyStr)
	t.Setenv("APP_PREVIOUS_KEYS", "invalid-key")

	ciphertext, err := Encrypt("data")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if _, err := Decrypt(ciphertext); err == nil || !strings.Contains(err.Error(), "failed to parse APP_PREVIOUS_KEYS") {
		t.Fatalf("Expected parse error for previous keys, got %v", err)
	}
}

func TestGetPreviousAppKeysTrimsWhitespaceAndSkipsEmpty(t *testing.T) {
	firstKey, firstKeyStr := generateKeyPair(t)
	secondKey, secondKeyStr := generateKeyPair(t)

	t.Setenv("APP_PREVIOUS_KEYS", "  "+firstKeyStr+" , , "+secondKeyStr+" , ")

	keys, err := GetPreviousAppKeys()
	if err != nil {
		t.Fatalf("GetPreviousAppKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("Expected 2 keys, got %d", len(keys))
	}
	if !bytes.Equal(keys[0], firstKey) || !bytes.Equal(keys[1], secondKey) {
		t.Fatalf("Keys did not match input order")
	}
}

func TestDecryptWithMixedKeyLengths(t *testing.T) {
	currentKey, currentKeyStr := generateKeyWithSize(t, 32)
	previousKey, previousKeyStr := generateKeyWithSize(t, 16)

	t.Setenv("APP_KEY", currentKeyStr)
	t.Setenv("APP_PREVIOUS_KEYS", previousKeyStr)

	ciphertext, err := encryptWithKey(previousKey, "legacy aes-128")
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	plaintext, err := Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if plaintext != "legacy aes-128" {
		t.Fatalf("Expected plaintext to match, got %q", plaintext)
	}

	ciphertext, err = Encrypt("current aes-256")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	plaintext, err = decryptWithKey(currentKey, ciphertext)
	if err != nil || plaintext != "current aes-256" {
		t.Fatalf("Expected decrypt with current key to succeed; got plaintext %q, err %v", plaintext, err)
	}
	if _, err := decryptWithKey(previousKey, ciphertext); err == nil {
		t.Fatalf("Expected previous AES-128 key to fail decrypting AES-256 ciphertext")
	}
}

func TestPkcs7UnpadErrors(t *testing.T) {
	if _, err := pkcs7Unpad([]byte{}); err == nil {
		t.Fatalf("expected error on empty input")
	}
	if _, err := pkcs7Unpad([]byte{1, 2, 0}); err == nil {
		t.Fatalf("expected error on zero padding")
	}
	if _, err := pkcs7Unpad([]byte{1, 2, 3, 2}); err == nil {
		t.Fatalf("expected error on invalid pattern")
	}
}

type failingReader struct{}

func (f failingReader) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestGenerateAppKeyRandError(t *testing.T) {
	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	if _, err := GenerateAppKey(); err == nil {
		t.Fatalf("expected error when rand fails")
	}
}

func TestDecryptWithKeyBase64Failure(t *testing.T) {
	if _, err := decryptWithKey(make([]byte, 16), "???"); err == nil || !strings.Contains(err.Error(), "base64 decode failed") {
		t.Fatalf("expected base64 decode failure")
	}
}

func TestDecryptWithKeyInvalidKeySize(t *testing.T) {
	_, keyStr := generateKeyPair(t)
	t.Setenv("APP_KEY", keyStr)

	ciphertext, err := Encrypt("data")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 17-byte key
	badKey := make([]byte, 17)

	// rebuild payload with MAC generated from the bad key so HMAC passes and cipher init fails
	raw, _ := base64.StdEncoding.DecodeString(ciphertext)
	var payload EncryptedPayload
	_ = json.Unmarshal(raw, &payload)
	ivBytes, _ := base64.StdEncoding.DecodeString(payload.IV)
	ctBytes, _ := base64.StdEncoding.DecodeString(payload.Value)
	payload.MAC = base64.StdEncoding.EncodeToString(computeHMACSHA256(append(ivBytes, ctBytes...), badKey))
	modified, _ := json.Marshal(payload)
	enc := base64.StdEncoding.EncodeToString(modified)

	if _, err := decryptWithKey(badKey, enc); err == nil || !strings.Contains(err.Error(), "invalid key size") {
		t.Fatalf("expected invalid key size error, got %v", err)
	}
}

func TestEncryptMarshalError(t *testing.T) {
	orig := jsonMarshal
	defer func() { jsonMarshal = orig }()

	jsonMarshal = func(v any) ([]byte, error) {
		return nil, errors.New("marshal boom")
	}

	key, _ := generateKeyPair(t)
	if _, err := encryptWithKey(key, "data"); err == nil || !strings.Contains(err.Error(), "marshal boom") {
		t.Fatalf("expected marshal error, got %v", err)
	}
}

func TestDumpExample(t *testing.T) {
	dumpExample("a", 1)
}
