// Package crypt provides authenticated AES-CBC encryption for application data.
//
// Existing Encrypt calls emit crypt's original payload format. EncryptForInterop
// explicitly selects the alternate interoperability envelope, while Decrypt accepts
// both formats and supports graceful key rotation.
package crypt
