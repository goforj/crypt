package crypt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// BenchmarkCipherEncrypt tracks writes of the current envelope.
func BenchmarkCipherEncrypt(b *testing.B) {
	cipher, err := New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := cipher.Encrypt("benchmark payload"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCipherDecryptBase64MAC tracks authenticated reads of the historical format.
func BenchmarkCipherDecryptBase64MAC(b *testing.B) {
	benchmarkDecrypt(b, key128Hex, base64MACFixtures[0].ciphertext)
}

// BenchmarkCipherDecryptHexMAC tracks authenticated reads of the current format.
func BenchmarkCipherDecryptHexMAC(b *testing.B) {
	benchmarkDecrypt(b, key128Hex, hexMACFixtures[0].ciphertext)
}

// benchmarkDecrypt prepares one ciphertext so benchmarks measure the read path only.
func benchmarkDecrypt(b *testing.B, keyHex string, encoded string) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		b.Fatal(err)
	}
	cipher, err := New(key)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := cipher.Decrypt(encoded); err != nil {
			b.Fatal(err)
		}
	}
}
