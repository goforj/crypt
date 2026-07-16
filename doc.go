// Package crypt provides authenticated AES-CBC encryption for application data.
//
// Encrypt emits the current hex-MAC envelope. Decrypt accepts both current and
// historical envelopes and supports graceful key rotation.
package crypt
