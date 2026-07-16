package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrInvalidKey indicates that a key is missing, malformed, or has an unsupported length.
var ErrInvalidKey = errors.New("crypt: invalid key")

// ErrInvalidPayload indicates that a ciphertext envelope is malformed or cannot be safely decrypted.
var ErrInvalidPayload = errors.New("crypt: invalid payload")

// ErrAuthentication indicates that no configured key authenticated a well-formed ciphertext.
var ErrAuthentication = errors.New("crypt: authentication failed")

var errNilCipher = errors.New("crypt: nil cipher")

type payloadFormat uint8

const (
	payloadFormatBase64MAC payloadFormat = iota
	payloadFormatHexMAC
)

// Cipher provides instance-based encryption and decryption with injected keys.
// Its key material is copied during construction, and a Cipher is safe for concurrent use.
// @group Encryption
// @behavior readonly
type Cipher struct {
	key          []byte
	previousKeys [][]byte
}

// EncryptedPayload describes crypt's historical base64-MAC ciphertext envelope.
//
// This type intentionally retains its original three-field shape so code using unkeyed
// composite literals remains source compatible. Alternate envelopes are parsed internally.
type EncryptedPayload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
}

// encryptedPayloadEnvelope accepts both supported CBC envelopes without changing EncryptedPayload.
type encryptedPayloadEnvelope struct {
	IV    string          `json:"iv"`
	Value string          `json:"value"`
	MAC   string          `json:"mac"`
	Tag   json.RawMessage `json:"tag"`
}

// hexMACEncryptedPayload preserves the current envelope's field order and explicit empty CBC tag.
type hexMACEncryptedPayload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
	Tag   string `json:"tag"`
}

// parsedEncryptedPayload holds the one-time validated envelope shared by all key attempts.
type parsedEncryptedPayload struct {
	format       payloadFormat
	iv           []byte
	ciphertext   []byte
	mac          []byte
	encodedIV    string
	encodedValue string
}

// New constructs a Cipher with an injected current key and optional previous keys.
// Keys must be 16 bytes (AES-128) or 32 bytes (AES-256). Inputs are copied.
// @group Key management
// @behavior readonly
func New(key []byte, previousKeys ...[]byte) (*Cipher, error) {
	current, err := cloneAndValidateAESKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid current key: %w", err)
	}

	previous := make([][]byte, 0, len(previousKeys))
	for index, key := range previousKeys {
		cloned, err := cloneAndValidateAESKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid previous key at index %d: %w", index, err)
		}
		previous = append(previous, cloned)
	}

	return &Cipher{
		key:          current,
		previousKeys: previous,
	}, nil
}

// NewFromEnv constructs a Cipher from APP_KEY and APP_PREVIOUS_KEYS.
// @group Key management
// @behavior readonly
func NewFromEnv() (*Cipher, error) {
	key, err := GetAppKey()
	if err != nil {
		return nil, err
	}

	previousKeys, err := GetPreviousAppKeys()
	if err != nil {
		return nil, err
	}

	return New(key, previousKeys...)
}

// Encrypt encrypts plaintext with the Cipher's current key using the hex-MAC CBC envelope.
// The envelope signs the base64 IV and ciphertext, encodes the MAC as lowercase hex, and includes an empty tag.
// @group Encryption
// @behavior readonly
//
// Example: encrypt with an injected key
//
//	key := make([]byte, 32)
//	c, _ := crypt.New(key)
//	ciphertext, err := c.Encrypt("secret")
//	godump.Dump(err == nil, ciphertext != "")
//	// #bool true
//	// #bool true
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if c == nil {
		return "", errNilCipher
	}
	return encryptWithKey(c.key, plaintext)
}

// Decrypt decrypts current and historical CBC envelopes.
// It authenticates with the current key first, followed by configured previous keys.
// @group Encryption
// @behavior readonly
func (c *Cipher) Decrypt(encodedPayload string) (string, error) {
	if c == nil {
		return "", errNilCipher
	}
	return decryptWithCandidateKeys(c.key, c.previousKeys, encodedPayload)
}

// GenerateAppKey generates a random AES-256 key using the base64-prefixed APP_KEY syntax.
// @group Key management
// @behavior readonly
//
// Example: generate an AES-256 key
//
//	key, _ := crypt.GenerateAppKey()
//	godump.Dump(key)
//	// #string "base64:..."
func GenerateAppKey() (string, error) {
	return generateAppKey(rand.Reader)
}

// GetAppKey retrieves the APP_KEY from the environment and parses it.
// @group Key management
// @behavior readonly
//
// Example: read APP_KEY and ensure the correct size
//
//	appKey, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_KEY", appKey)
//	key, err := crypt.GetAppKey()
//	godump.Dump(len(key), err)
//	// #int 32
//	// #error <nil>
func GetAppKey() ([]byte, error) {
	key := os.Getenv("APP_KEY")
	if key == "" {
		return nil, fmt.Errorf("%w: APP_KEY is not set", ErrInvalidKey)
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
//	oldKeyA, _ := crypt.GenerateAppKey()
//	oldKeyB, _ := crypt.GenerateAppKey()
//	// APP_PREVIOUS_KEYS is a comma-separated list.
//	_ = os.Setenv("APP_PREVIOUS_KEYS", oldKeyA+", "+oldKeyB)
//	keys, err := crypt.GetPreviousAppKeys()
//	godump.Dump(len(keys), err)
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

// ReadAppKey parses a base64-prefixed AES-128 or AES-256 application key.
// @group Key management
// @behavior readonly
//
// Example: parse AES-128 and AES-256 keys
//
//	// Build a 16-byte (AES-128) key string manually.
//	raw16 := make([]byte, 16)
//	_, _ = rand.Read(raw16)
//	key16 := "base64:" + base64.StdEncoding.EncodeToString(raw16)
//
//	// Generate a 32-byte (AES-256) key string with the helper.
//	key32, _ := crypt.GenerateAppKey()
//
//	parsed16, _ := crypt.ReadAppKey(key16)
//	parsed32, _ := crypt.ReadAppKey(key32)
//	godump.Dump(len(parsed16), len(parsed32))
//	// #int 16
//	// #int 32
func ReadAppKey(key string) ([]byte, error) {
	const prefix = "base64:"
	if !strings.HasPrefix(key, prefix) {
		return nil, fmt.Errorf("%w: unsupported or missing key prefix", ErrInvalidKey)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(key, prefix))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed base64", ErrInvalidKey)
	}
	if len(decoded) != 16 && len(decoded) != 32 {
		return nil, fmt.Errorf("%w: key must decode to 16 or 32 bytes", ErrInvalidKey)
	}
	return decoded, nil
}

// Encrypt encrypts plaintext with APP_KEY using the hex-MAC CBC envelope.
// The envelope signs the base64 IV and ciphertext, encodes the MAC as lowercase hex, and includes an empty tag.
// @group Encryption
// @behavior readonly
//
// Example: encrypt with current APP_KEY
//
//	appKey, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_KEY", appKey)
//	ciphertext, err := crypt.Encrypt("secret")
//	godump.Dump(err == nil, ciphertext != "")
//	// #bool true
//	// #bool true
func Encrypt(plaintext string) (string, error) {
	key, err := GetAppKey()
	if err != nil {
		return "", err
	}
	return encryptWithKey(key, plaintext)
}

// Decrypt decrypts either supported payload format using APP_KEY and APP_PREVIOUS_KEYS.
// @group Encryption
// @behavior readonly
//
// Example: decrypt using current key
//
//	appKey, _ := crypt.GenerateAppKey()
//	_ = os.Setenv("APP_KEY", appKey)
//	ciphertext, _ := crypt.Encrypt("secret")
//	plaintext, _ := crypt.Decrypt(ciphertext)
//	godump.Dump(plaintext)
//	// #string "secret"
//
// Example: decrypt ciphertext encrypted with a previous key
//
//	oldAppKey, _ := crypt.GenerateAppKey()
//	newAppKey, _ := crypt.GenerateAppKey()
//
//	// Encrypt with the old key first.
//	_ = os.Setenv("APP_KEY", oldAppKey)
//	rotatedCiphertext, _ := crypt.Encrypt("rotated")
//
//	// Rotate to a new current key, but keep the old key in APP_PREVIOUS_KEYS.
//	_ = os.Setenv("APP_KEY", newAppKey)
//	_ = os.Setenv("APP_PREVIOUS_KEYS", oldAppKey)
//	plaintext, err := crypt.Decrypt(rotatedCiphertext)
//	godump.Dump(plaintext, err)
//	// #string "rotated"
//	// #error <nil>
func Decrypt(encodedPayload string) (string, error) {
	cipher, err := NewFromEnv()
	if err != nil {
		return "", err
	}
	return cipher.Decrypt(encodedPayload)
}

// generateAppKey isolates entropy injection so error paths are tested without mutable globals.
func generateAppKey(random io.Reader) (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(random, key); err != nil {
		return "", fmt.Errorf("generate application key: %w", err)
	}
	return "base64:" + base64.StdEncoding.EncodeToString(key), nil
}

// cloneAndValidateAESKey prevents caller mutations from changing a constructed Cipher.
func cloneAndValidateAESKey(key []byte) ([]byte, error) {
	if err := validateAESKey(key); err != nil {
		return nil, err
	}
	return append([]byte(nil), key...), nil
}

// validateAESKey rejects zero-value and manually assembled Cipher key states deterministically.
func validateAESKey(key []byte) error {
	if len(key) != 16 && len(key) != 32 {
		return fmt.Errorf("%w: key must be 16 or 32 bytes", ErrInvalidKey)
	}
	return nil
}

// pkcs7Pad always adds padding so a block-aligned plaintext remains unambiguous.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// pkcs7Unpad rejects every malformed padding shape before returning plaintext bytes.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty padded plaintext", ErrInvalidPayload)
	}
	padding := data[len(data)-1]
	if padding == 0 || int(padding) > len(data) {
		return nil, fmt.Errorf("%w: invalid padding", ErrInvalidPayload)
	}
	for _, value := range data[len(data)-int(padding):] {
		if value != padding {
			return nil, fmt.Errorf("%w: invalid padding", ErrInvalidPayload)
		}
	}
	return data[:len(data)-int(padding)], nil
}

// encryptWithKey emits the current hex-MAC CBC envelope.
func encryptWithKey(key []byte, plaintext string) (string, error) {
	return encryptWithKeyAndReader(key, plaintext, rand.Reader)
}

// encryptWithKeyAndReader accepts an entropy source so exact wire fixtures remain reproducible.
func encryptWithKeyAndReader(key []byte, plaintext string, random io.Reader) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("%w: key must be 16 or 32 bytes", ErrInvalidKey)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(random, iv); err != nil {
		return "", fmt.Errorf("generate initialization vector: %w", err)
	}

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	encodedIV := base64.StdEncoding.EncodeToString(iv)
	encodedValue := base64.StdEncoding.EncodeToString(ciphertext)

	mac := computeHMACSHA256([]byte(encodedIV+encodedValue), key)
	payload := hexMACEncryptedPayload{
		IV:    encodedIV,
		Value: encodedValue,
		MAC:   hex.EncodeToString(mac),
		Tag:   "",
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode encrypted payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(jsonData), nil
}

// decryptWithCandidateKeys parses once so malformed envelopes do not create key-loop-dependent errors.
func decryptWithCandidateKeys(currentKey []byte, previousKeys [][]byte, encodedPayload string) (string, error) {
	if err := validateAESKey(currentKey); err != nil {
		return "", fmt.Errorf("invalid current key: %w", err)
	}
	for index, key := range previousKeys {
		if err := validateAESKey(key); err != nil {
			return "", fmt.Errorf("invalid previous key at index %d: %w", index, err)
		}
	}

	payload, err := parseEncryptedPayload(encodedPayload)
	if err != nil {
		return "", err
	}

	keys := make([][]byte, 0, 1+len(previousKeys))
	keys = append(keys, currentKey)
	keys = append(keys, previousKeys...)
	for _, key := range keys {
		if !payload.authenticates(key) {
			continue
		}
		return decryptAuthenticatedPayload(key, payload)
	}
	return "", ErrAuthentication
}

// decryptWithKey retains the historical helper while using the total shared parser.
func decryptWithKey(key []byte, encodedPayload string) (string, error) {
	return decryptWithCandidateKeys(key, nil, encodedPayload)
}

// parseEncryptedPayload validates all envelope structure before any key is attempted.
func parseEncryptedPayload(encodedPayload string) (parsedEncryptedPayload, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		return parsedEncryptedPayload{}, fmt.Errorf("%w: malformed outer base64", ErrInvalidPayload)
	}

	var envelope encryptedPayloadEnvelope
	if err := json.Unmarshal(jsonBytes, &envelope); err != nil {
		return parsedEncryptedPayload{}, fmt.Errorf("%w: malformed JSON envelope", ErrInvalidPayload)
	}
	if err := validateCBCTag(envelope.Tag); err != nil {
		return parsedEncryptedPayload{}, err
	}

	iv, err := base64.StdEncoding.DecodeString(envelope.IV)
	if err != nil || len(iv) != aes.BlockSize {
		return parsedEncryptedPayload{}, fmt.Errorf("%w: IV must be base64 for 16 bytes", ErrInvalidPayload)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Value)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return parsedEncryptedPayload{}, fmt.Errorf("%w: ciphertext must be non-empty base64 for complete AES blocks", ErrInvalidPayload)
	}

	format, mac, err := parsePayloadMAC(envelope.MAC)
	if err != nil {
		return parsedEncryptedPayload{}, err
	}
	return parsedEncryptedPayload{
		format:       format,
		iv:           iv,
		ciphertext:   ciphertext,
		mac:          mac,
		encodedIV:    envelope.IV,
		encodedValue: envelope.Value,
	}, nil
}

// validateCBCTag accepts empty or omitted CBC tags but rejects AEAD data under CBC.
func validateCBCTag(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}

	var tag string
	if err := json.Unmarshal(trimmed, &tag); err != nil {
		return fmt.Errorf("%w: CBC tag must be a string", ErrInvalidPayload)
	}
	if tag != "" {
		return fmt.Errorf("%w: CBC payloads cannot contain an authentication tag", ErrInvalidPayload)
	}
	return nil
}

// parsePayloadMAC identifies formats only from each format's canonical, non-overlapping MAC shape.
func parsePayloadMAC(encodedMAC string) (payloadFormat, []byte, error) {
	if len(encodedMAC) == sha256.Size*2 && isLowerHex(encodedMAC) {
		mac, err := hex.DecodeString(encodedMAC)
		if err == nil {
			return payloadFormatHexMAC, mac, nil
		}
	}

	mac, err := base64.StdEncoding.Strict().DecodeString(encodedMAC)
	if err == nil && len(mac) == sha256.Size && base64.StdEncoding.EncodeToString(mac) == encodedMAC {
		return payloadFormatBase64MAC, mac, nil
	}
	return 0, nil, fmt.Errorf("%w: MAC has an unsupported encoding", ErrInvalidPayload)
}

// isLowerHex enforces canonical lowercase hexadecimal MAC output rather than accepting ambiguous variants.
func isLowerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// authenticates checks the selected format's exact signed byte sequence in constant time.
func (p parsedEncryptedPayload) authenticates(key []byte) bool {
	var expected []byte
	switch p.format {
	case payloadFormatBase64MAC:
		expected = computeHMACSHA256Parts(key, p.iv, p.ciphertext)
	case payloadFormatHexMAC:
		expected = computeHMACSHA256([]byte(p.encodedIV+p.encodedValue), key)
	default:
		return false
	}
	return hmac.Equal(expected, p.mac)
}

// decryptAuthenticatedPayload performs CBC only after length checks and successful authentication.
func decryptAuthenticatedPayload(key []byte, payload parsedEncryptedPayload) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("%w: key must be 16 or 32 bytes", ErrInvalidKey)
	}

	plaintext := append([]byte(nil), payload.ciphertext...)
	cipher.NewCBCDecrypter(block, payload.iv).CryptBlocks(plaintext, plaintext)
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

// computeHMACSHA256 computes HMAC-SHA256 over one byte slice.
func computeHMACSHA256(data []byte, key []byte) []byte {
	return computeHMACSHA256Parts(key, data)
}

// computeHMACSHA256Parts avoids temporary concatenation while preserving byte-for-byte MAC input.
func computeHMACSHA256Parts(key []byte, parts ...[]byte) []byte {
	hash := hmac.New(sha256.New, key)
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}
