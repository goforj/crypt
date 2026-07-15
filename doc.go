// Package crypt provides authenticated AES-CBC encryption for application data.
//
// Existing Encrypt calls emit crypt's original payload format. EncryptLaravel is
// an explicit interoperability mode for Laravel's CBC encryptString format, while
// Decrypt accepts both formats and supports graceful key rotation.
package crypt
