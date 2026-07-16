package crypt

import (
	"bytes"
	"testing"
)

// BenchmarkCipherEncryptLegacy tracks the cost of preserving the original wire format.
func BenchmarkCipherEncryptLegacy(b *testing.B) {
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

// BenchmarkCipherEncryptForInterop tracks the explicit interoperability writer.
func BenchmarkCipherEncryptForInterop(b *testing.B) {
	cipher, err := New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := cipher.EncryptForInterop("benchmark payload"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCipherDecryptLegacy tracks authenticated reads of the original format.
func BenchmarkCipherDecryptLegacy(b *testing.B) {
	benchmarkDecrypt(b, payloadFormatLegacy)
}

// BenchmarkCipherDecryptInterop tracks authenticated interoperability reads.
func BenchmarkCipherDecryptInterop(b *testing.B) {
	benchmarkDecrypt(b, payloadFormatInterop)
}

// benchmarkDecrypt prepares one ciphertext so benchmarks measure the read path only.
func benchmarkDecrypt(b *testing.B, format payloadFormat) {
	key := bytes.Repeat([]byte{0x42}, 32)
	cipher, err := New(key)
	if err != nil {
		b.Fatal(err)
	}
	encoded, err := encryptWithKeyAndReader(key, "benchmark payload", format, bytes.NewReader(bytes.Repeat([]byte{1}, 16)))
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
