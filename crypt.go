package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/goforj/godump"
	"io"
	"os"
	"strings"
)

var jsonMarshal = json.Marshal

// GenerateAppKey generates a random base64 app key prefixed with "base64:".
// @group Key management
// @behavior readonly
//
// Example: generate an AES-256 key
//
//	key, _ := crypt.GenerateAppKey()
//	godump.Dump(key)
//
//	// #string "base64:..."
func GenerateAppKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	return "base64:" + encoded, nil
}

// GetAppKey retrieves the APP_KEY from the environment and parses it.
// @group Key management
// @behavior readonly
//
// Example: read APP_KEY and ensure the correct size
//
//	keyStr, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_KEY", keyStr)
//	key, err := crypt.GetAppKey()
//	godump.Dump(len(key), err)
//
//	// #int 32
//	// #error <nil>
func GetAppKey() ([]byte, error) {
	key := os.Getenv("APP_KEY")
	if key == "" {
		return nil, errors.New("APP_KEY is not set in environment")
	}
	return ReadAppKey(key)
}

// GetPreviousAppKeys retrieves and parses APP_PREVIOUS_KEYS from the environment.
// Keys are expected to be comma-delimited and prefixed with "base64:".
// @group Key management
// @behavior readonly
//
// Example: parse two previous keys (mixed AES-128/256)
//
//	k1, _ := crypt.GenerateAppKey()
//	k2, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_PREVIOUS_KEYS", k1+", "+k2)
//	keys, err := crypt.GetPreviousAppKeys()
//	godump.Dump(len(keys), err)
//
//	// #int 2
//	// #error <nil>
func GetPreviousAppKeys() ([][]byte, error) {
	previous := strings.TrimSpace(os.Getenv("APP_PREVIOUS_KEYS"))
	if previous == "" {
		return nil, nil
	}

	parts := strings.Split(previous, ",")
	keys := make([][]byte, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, err := ReadAppKey(part)
		if err != nil {
			return nil, fmt.Errorf("failed to parse APP_PREVIOUS_KEYS: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// ReadAppKey parses a base64 encoded app key with "base64:" prefix.
// Accepts 16-byte keys (AES-128) or 32-byte keys (AES-256) after decoding.
// @group Key management
// @behavior readonly
//
// Example: parse AES-128 and AES-256 keys
//
//	key128raw := make([]byte, 16)
//	_, _ = rand.Read(key128raw)
//	key128str := "base64:" + base64.StdEncoding.EncodeToString(key128raw)
//
//	key256str, _ := crypt.GenerateAppKey()
//
//	key128, _ := crypt.ReadAppKey(key128str)
//	key256, _ := crypt.ReadAppKey(key256str)
//	godump.Dump(len(key128), len(key256))
//
//	// #int 16
//	// #int 32
func ReadAppKey(key string) ([]byte, error) {
	const prefix = "base64:"
	if len(key) < len(prefix) || key[:len(prefix)] != prefix {
		return nil, fmt.Errorf("unsupported or missing key prefix")
	}
	decoded, err := base64.StdEncoding.DecodeString(key[len(prefix):])
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 && len(decoded) != 16 {
		return nil, fmt.Errorf("key must be 16 or 32 bytes after decoding")
	}
	return decoded, nil
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7 semantics.
// @group Padding
// @behavior pure
//
// Example: pad short block
//
//	p := crypt.pkcs7Pad([]byte("abc"), 4)
//	godump.Dump(p)
//
//	// #[]uint8 [
//	//   0 => 97 #uint8
//	//   1 => 98 #uint8
//	//   2 => 99 #uint8
//	//   3 => 1  #uint8
//	// ]
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from data.
// @group Padding
// @behavior readonly
//
// Example: unpad valid data
//
//	out, _ := crypt.pkcs7Unpad([]byte{97, 98, 99, 1})
//	godump.Dump(string(out))
//
//	// #string "abc"
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid padding size")
	}
	padding := data[len(data)-1]
	if int(padding) > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	for _, b := range data[len(data)-int(padding):] {
		if b != padding {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-int(padding)], nil
}

// EncryptedPayload is the JSON structure wrapped in base64 used for ciphertext.
type EncryptedPayload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
}

// Encrypt encrypts a plaintext using the APP_KEY from environment.
// @group Encryption
// @behavior readonly
//
// Example: encrypt with current APP_KEY
//
//	keyStr, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_KEY", keyStr)
//	ciphertext, err := crypt.Encrypt("secret")
//	godump.Dump(err == nil, ciphertext != "")
//
//	// #bool true
//	// #bool true
func Encrypt(plaintext string) (string, error) {
	key, err := GetAppKey()
	if err != nil {
		return "", err
	}
	return encryptWithKey(key, plaintext)
}

// Decrypt decrypts an encrypted payload using the APP_KEY from environment.
// Falls back to APP_PREVIOUS_KEYS when the current key cannot decrypt.
// @group Encryption
// @behavior readonly
//
// Example: decrypt using current key
//
//	keyStr, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_KEY", keyStr)
//	c, _ := crypt.Encrypt("secret")
//	p, _ := crypt.Decrypt(c)
//	godump.Dump(p)
//
//	// #string "secret"
//
// Example: decrypt ciphertext encrypted with a previous key
//
//	oldKeyStr, _ := crypt.GenerateAppKey()
//	newKeyStr, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_KEY", oldKeyStr)
//	oldCipher, _ := crypt.Encrypt("rotated")
//	_ = os.Setenv("APP_KEY", newKeyStr)
//	_ = os.Setenv("APP_PREVIOUS_KEYS", oldKeyStr)
//	plain, err := crypt.Decrypt(oldCipher)
//	godump.Dump(plain, err)
//
//	// #string "rotated"
//	// #error <nil>
func Decrypt(encodedPayload string) (string, error) {
	key, err := GetAppKey()
	if err != nil {
		return "", err
	}

	previousKeys, err := GetPreviousAppKeys()
	if err != nil {
		return "", err
	}

	keys := make([][]byte, 0, 1+len(previousKeys))
	keys = append(keys, key)
	keys = append(keys, previousKeys...)

	var lastErr error
	for _, k := range keys {
		plain, decErr := decryptWithKey(k, encodedPayload)
		if decErr == nil {
			return plain, nil
		}
		lastErr = decErr
	}
	return "", fmt.Errorf("failed to decrypt with current or previous keys: %w", lastErr)
}

// encryptWithKey encrypts plaintext using the provided AES key (16 or 32 bytes).
// Intended for internal use; prefer Encrypt for env-driven keys.
// @group Encryption
// @behavior readonly
func encryptWithKey(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	ivB64 := base64.StdEncoding.EncodeToString(iv)
	valB64 := base64.StdEncoding.EncodeToString(ciphertext)
	mac := computeHMACSHA256(append(iv, ciphertext...), key)
	macB64 := base64.StdEncoding.EncodeToString(mac)

	payload := EncryptedPayload{IV: ivB64, Value: valB64, MAC: macB64}
	jsonData, err := jsonMarshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonData), nil
}

// decryptWithKey attempts to decrypt an encoded payload using the provided AES key.
// Intended for internal use; prefer Decrypt for env-driven keys and rotation.
// @group Encryption
// @behavior readonly
func decryptWithKey(key []byte, encodedPayload string) (string, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	var payload EncryptedPayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return "", fmt.Errorf("json decode failed: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil {
		return "", fmt.Errorf("iv decode failed: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Value)
	if err != nil {
		return "", fmt.Errorf("value decode failed: %w", err)
	}
	mac, err := base64.StdEncoding.DecodeString(payload.MAC)
	if err != nil {
		return "", fmt.Errorf("mac decode failed: %w", err)
	}

	expectedMAC := computeHMACSHA256(append(iv, ciphertext...), key)
	if !hmac.Equal(expectedMAC, mac) {
		return "", errors.New("HMAC validation failed")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	unpadded, err := pkcs7Unpad(ciphertext)
	if err != nil {
		return "", err
	}

	return string(unpadded), nil
}

// computeHMACSHA256 computes HMAC-SHA256 over data with the given key.
// @group MAC
// @behavior pure
//
// Example: produce deterministic MAC
//
//	m := crypt.computeHMACSHA256([]byte("msg"), []byte("key"))
//	godump.Dump(len(m))
//
//	// #int 32
func computeHMACSHA256(data []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// dumpExample is a no-op wrapper to keep the godump import live for doc examples.
func dumpExample(values ...interface{}) {
	godump.Dump(values...)
}
