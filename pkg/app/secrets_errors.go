// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package app

import "fmt"

// ErrNilSecretsConfig is returned when a nil SecretsConfig is provided.
type ErrNilSecretsConfig struct{}

func (e ErrNilSecretsConfig) Error() string {
	return "secrets config cannot be nil"
}

// ErrSetupSecretResolvers is returned when setting up secret resolvers fails.
type ErrSetupSecretResolvers struct {
	Cause error
}

func (e ErrSetupSecretResolvers) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to setup secret resolvers: %v", e.Cause)
	}
	return "failed to setup secret resolvers"
}

func (e ErrSetupSecretResolvers) Unwrap() error {
	return e.Cause
}

// ErrCreateSecretManager is returned when creating the secret manager fails.
type ErrCreateSecretManager struct {
	Cause error
}

func (e ErrCreateSecretManager) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to create secret manager: %v", e.Cause)
	}
	return "failed to create secret manager"
}

func (e ErrCreateSecretManager) Unwrap() error {
	return e.Cause
}

// ErrProcessSecrets is returned when processing secrets fails.
type ErrProcessSecrets struct {
	Cause error
}

func (e ErrProcessSecrets) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to process secrets: %v", e.Cause)
	}
	return "failed to process secrets"
}

func (e ErrProcessSecrets) Unwrap() error {
	return e.Cause
}

// ErrUpdateConfigFile is returned when updating the config file fails.
type ErrUpdateConfigFile struct {
	Cause error
}

func (e ErrUpdateConfigFile) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to update config file: %v", e.Cause)
	}
	return "failed to update config file"
}

func (e ErrUpdateConfigFile) Unwrap() error {
	return e.Cause
}

// ErrTPMNotAvailable is returned when TPM is required but not available.
type ErrTPMNotAvailable struct{}

func (e ErrTPMNotAvailable) Error() string {
	return "TPM is not available"
}

// ErrIDevIDNotConfigured is returned when IDevID is required but not configured.
type ErrIDevIDNotConfigured struct{}

func (e ErrIDevIDNotConfigured) Error() string {
	return "IDevID is not configured"
}

// ErrPlatformKSNotAvailable is returned when PlatformKeyStore is required but not available.
type ErrPlatformKSNotAvailable struct{}

func (e ErrPlatformKSNotAvailable) Error() string {
	return "platform keystore is not available"
}

// ErrGetIDevIDAttrs is returned when getting IDevID attributes fails.
type ErrGetIDevIDAttrs struct {
	Cause error
}

func (e ErrGetIDevIDAttrs) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to get IDevID attributes: %v", e.Cause)
	}
	return "failed to get IDevID attributes"
}

func (e ErrGetIDevIDAttrs) Unwrap() error {
	return e.Cause
}

// ErrGetDecrypter is returned when getting a decrypter fails.
type ErrGetDecrypter struct {
	Cause error
}

func (e ErrGetDecrypter) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to get decrypter: %v", e.Cause)
	}
	return "failed to get decrypter"
}

func (e ErrGetDecrypter) Unwrap() error {
	return e.Cause
}

// ErrContextCanceled is returned when the context is canceled during operation.
type ErrContextCanceled struct {
	Cause error
}

func (e ErrContextCanceled) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("context canceled: %v", e.Cause)
	}
	return "context canceled"
}

func (e ErrContextCanceled) Unwrap() error {
	return e.Cause
}

// ErrKMSNotAvailable is returned when KMS is required but not available.
type ErrKMSNotAvailable struct{}

func (e ErrKMSNotAvailable) Error() string {
	return "KMS service is not available"
}

// ErrInvalidKMSURI is returned when a KMS URI is malformed.
type ErrInvalidKMSURI struct {
	URI    string
	Reason string
}

func (e ErrInvalidKMSURI) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid KMS URI %q: %s", e.URI, e.Reason)
	}
	return fmt.Sprintf("invalid KMS URI: %s", e.URI)
}

// ErrKMSGetFailed is returned when retrieving a secret from KMS fails.
type ErrKMSGetFailed struct {
	Path  string
	Cause error
}

func (e ErrKMSGetFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to get secret from KMS at %s: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to get secret from KMS at %s", e.Path)
}

func (e ErrKMSGetFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSStoreFailed is returned when storing a secret in KMS fails.
type ErrKMSStoreFailed struct {
	Path  string
	Cause error
}

func (e ErrKMSStoreFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to store secret in KMS at %s: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to store secret in KMS at %s", e.Path)
}

func (e ErrKMSStoreFailed) Unwrap() error {
	return e.Cause
}

// ErrSecretsServiceNotAvailable is returned when SecretsService is required but not available.
type ErrSecretsServiceNotAvailable struct{}

func (e ErrSecretsServiceNotAvailable) Error() string {
	return "secrets service is not available"
}

// ErrSecretsGetFailed is returned when retrieving a secret from SecretsService fails.
type ErrSecretsGetFailed struct {
	Path  string
	Cause error
}

func (e ErrSecretsGetFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to get secret at %s: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to get secret at %s", e.Path)
}

func (e ErrSecretsGetFailed) Unwrap() error {
	return e.Cause
}

// ErrSecretsStoreFailed is returned when storing a secret in SecretsService fails.
type ErrSecretsStoreFailed struct {
	Path  string
	Cause error
}

func (e ErrSecretsStoreFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to store secret at %s: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to store secret at %s", e.Path)
}

func (e ErrSecretsStoreFailed) Unwrap() error {
	return e.Cause
}

// ErrDynamicSecretsNotAvailable is returned when the DynamicSecrets service is required but not available.
type ErrDynamicSecretsNotAvailable struct{}

func (e ErrDynamicSecretsNotAvailable) Error() string {
	return "dynamic secrets service is not available"
}

// ErrInvalidDynamicURI is returned when a dynamic:// URI is malformed.
type ErrInvalidDynamicURI struct {
	URI    string
	Reason string
}

func (e ErrInvalidDynamicURI) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid dynamic URI %q: %s", e.URI, e.Reason)
	}
	return fmt.Sprintf("invalid dynamic URI: %s", e.URI)
}

// ErrDynamicSecretGenerateFailed is returned when generating a dynamic credential fails.
type ErrDynamicSecretGenerateFailed struct {
	RoleName string
	Cause    error
}

func (e ErrDynamicSecretGenerateFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to generate dynamic credential for role %q: %v", e.RoleName, e.Cause)
	}
	return fmt.Sprintf("failed to generate dynamic credential for role %q", e.RoleName)
}

func (e ErrDynamicSecretGenerateFailed) Unwrap() error {
	return e.Cause
}

// ErrXKMSNotAvailable is returned when the XKMS adapter is required but not available.
type ErrXKMSNotAvailable struct{}

func (e ErrXKMSNotAvailable) Error() string {
	return "XKMS adapter is not available"
}

// ErrInvalidXKMSURI is returned when an xkms:// URI is malformed.
type ErrInvalidXKMSURI struct {
	URI    string
	Reason string
}

func (e ErrInvalidXKMSURI) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid XKMS URI %q: %s", e.URI, e.Reason)
	}
	return fmt.Sprintf("invalid XKMS URI: %s", e.URI)
}

// ErrXKMSUnsealFailed is returned when unsealing data via XKMS fails.
type ErrXKMSUnsealFailed struct {
	Backend string
	KeyID   string
	Cause   error
}

func (e ErrXKMSUnsealFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to unseal via XKMS backend %q key %q: %v", e.Backend, e.KeyID, e.Cause)
	}
	return fmt.Sprintf("failed to unseal via XKMS backend %q key %q", e.Backend, e.KeyID)
}

func (e ErrXKMSUnsealFailed) Unwrap() error {
	return e.Cause
}

// ErrXKMSGetKeyFailed is returned when retrieving a key from XKMS fails.
type ErrXKMSGetKeyFailed struct {
	Backend string
	KeyID   string
	Cause   error
}

func (e ErrXKMSGetKeyFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to get key from XKMS backend %q key %q: %v", e.Backend, e.KeyID, e.Cause)
	}
	return fmt.Sprintf("failed to get key from XKMS backend %q key %q", e.Backend, e.KeyID)
}

func (e ErrXKMSGetKeyFailed) Unwrap() error {
	return e.Cause
}

// ErrConfigDecryptFailed is returned when decrypting a config value with the
// platform config-encryption key fails.
type ErrConfigDecryptFailed struct {
	Cause error
}

func (e ErrConfigDecryptFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("config decryption failed: %v", e.Cause)
	}
	return "config decryption failed"
}

func (e ErrConfigDecryptFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidCiphertextLength is returned when the ciphertext is too short
// to contain a valid nonce and ciphertext.
type ErrInvalidCiphertextLength struct {
	Length   int
	MinBytes int
}

func (e ErrInvalidCiphertextLength) Error() string {
	return fmt.Sprintf("ciphertext too short: got %d bytes, need at least %d", e.Length, e.MinBytes)
}

// ErrEmptyDecryptResult is returned when the KMS decrypt operation returns
// an empty plaintext.
type ErrEmptyDecryptResult struct{}

func (e ErrEmptyDecryptResult) Error() string {
	return "decrypt returned empty plaintext"
}

// ErrConfigKeyGenerateFailed is returned when generating the platform
// config-encryption key fails.
type ErrConfigKeyGenerateFailed struct {
	Cause error
}

func (e ErrConfigKeyGenerateFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to generate platform config-encryption key: %v", e.Cause)
	}
	return "failed to generate platform config-encryption key"
}

func (e ErrConfigKeyGenerateFailed) Unwrap() error {
	return e.Cause
}
