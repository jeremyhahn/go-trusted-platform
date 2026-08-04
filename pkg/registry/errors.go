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

package registry

import "fmt"

// ErrAttestationRequired is returned when a client attempts to access
// the registry without providing attestation evidence.
type ErrAttestationRequired struct{}

func (e ErrAttestationRequired) Error() string {
	return "registry: attestation evidence required for registry access"
}

// ErrAttestationFailed is returned when attestation verification fails.
type ErrAttestationFailed struct {
	Reason string
}

func (e ErrAttestationFailed) Error() string {
	return fmt.Sprintf("registry: attestation verification failed: %s", e.Reason)
}

// ErrInvalidQuote is returned when a TPM quote is malformed or cannot be verified.
type ErrInvalidQuote struct {
	Reason string
	Cause  error
}

func (e ErrInvalidQuote) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("registry: invalid TPM quote: %v", e.Cause)
	}
	if e.Reason != "" {
		return fmt.Sprintf("registry: invalid TPM quote: %s", e.Reason)
	}
	return "registry: invalid TPM quote"
}

func (e ErrInvalidQuote) Unwrap() error {
	return e.Cause
}

// ErrAccessDenied is returned when access is denied based on policy evaluation.
type ErrAccessDenied struct {
	Subject  string
	Resource string
	Reason   string
}

func (e ErrAccessDenied) Error() string {
	if e.Subject != "" && e.Resource != "" {
		return fmt.Sprintf("registry: access denied: subject %s cannot access %s: %s", e.Subject, e.Resource, e.Reason)
	}
	return fmt.Sprintf("registry: access denied: %s", e.Reason)
}

// ErrImageNotFound is returned when a requested image does not exist.
type ErrImageNotFound struct {
	Reference string
}

func (e ErrImageNotFound) Error() string {
	return fmt.Sprintf("registry: image not found: %s", e.Reference)
}

// ErrImageExists is returned when attempting to push an image that already exists
// and overwrite is not allowed.
type ErrImageExists struct {
	Reference string
}

func (e ErrImageExists) Error() string {
	return fmt.Sprintf("registry: image already exists: %s", e.Reference)
}

// ErrDecryptionFailed is returned when image decryption fails.
type ErrDecryptionFailed struct {
	Reference string
	LayerID   string
	Cause     error
}

func (e ErrDecryptionFailed) Error() string {
	if e.LayerID != "" && e.Cause != nil {
		return fmt.Sprintf("registry: failed to decrypt layer %s: %v", e.LayerID, e.Cause)
	}
	if e.Reference != "" && e.Cause != nil {
		return fmt.Sprintf("registry: failed to decrypt image %s: %v", e.Reference, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("registry: decryption failed: %v", e.Cause)
	}
	return "registry: decryption failed"
}

func (e ErrDecryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrEncryptionFailed is returned when image encryption fails.
type ErrEncryptionFailed struct {
	Reference string
	LayerID   string
	Cause     error
}

func (e ErrEncryptionFailed) Error() string {
	if e.LayerID != "" && e.Cause != nil {
		return fmt.Sprintf("registry: failed to encrypt layer %s: %v", e.LayerID, e.Cause)
	}
	if e.Reference != "" && e.Cause != nil {
		return fmt.Sprintf("registry: failed to encrypt image %s: %v", e.Reference, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("registry: encryption failed: %v", e.Cause)
	}
	return "registry: encryption failed"
}

func (e ErrEncryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrStorageError is returned when a storage operation fails.
type ErrStorageError struct {
	Operation string
	Key       string
	Cause     error
}

func (e ErrStorageError) Error() string {
	if e.Key != "" && e.Cause != nil {
		return fmt.Sprintf("registry: storage error during %s for %s: %v", e.Operation, e.Key, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("registry: storage error during %s: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("registry: storage error during %s", e.Operation)
}

func (e ErrStorageError) Unwrap() error {
	return e.Cause
}

// ErrRegistryNotInitialized is returned when operations are attempted
// on an uninitialized registry.
type ErrRegistryNotInitialized struct{}

func (e ErrRegistryNotInitialized) Error() string {
	return "registry: registry not initialized"
}

// ErrRegistryClosed is returned when operations are attempted on a closed registry.
type ErrRegistryClosed struct{}

func (e ErrRegistryClosed) Error() string {
	return "registry: registry is closed"
}

// ErrInvalidImageRef is returned when an image reference is malformed.
type ErrInvalidImageRef struct {
	Reference string
	Reason    string
}

func (e ErrInvalidImageRef) Error() string {
	return fmt.Sprintf("registry: invalid image reference %q: %s", e.Reference, e.Reason)
}

// ErrBlobNotFound is returned when a specific blob is not found.
type ErrBlobNotFound struct {
	Digest string
}

func (e ErrBlobNotFound) Error() string {
	return fmt.Sprintf("registry: blob not found: %s", e.Digest)
}

// ErrManifestNotFound is returned when an image manifest is not found.
type ErrManifestNotFound struct {
	Reference string
}

func (e ErrManifestNotFound) Error() string {
	return fmt.Sprintf("registry: manifest not found: %s", e.Reference)
}

// ErrInvalidManifest is returned when a manifest is malformed.
type ErrInvalidManifest struct {
	Reference string
	Reason    string
}

func (e ErrInvalidManifest) Error() string {
	return fmt.Sprintf("registry: invalid manifest for %s: %s", e.Reference, e.Reason)
}

// ErrKeyNotFound is returned when an encryption key is not found.
type ErrKeyNotFound struct {
	KeyID string
}

func (e ErrKeyNotFound) Error() string {
	return fmt.Sprintf("registry: encryption key not found: %s", e.KeyID)
}

// ErrKeyCreationFailed is returned when key creation fails.
type ErrKeyCreationFailed struct {
	KeyID string
	Cause error
}

func (e ErrKeyCreationFailed) Error() string {
	if e.KeyID != "" && e.Cause != nil {
		return fmt.Sprintf("registry: failed to create key %s: %v", e.KeyID, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("registry: key creation failed: %v", e.Cause)
	}
	return "registry: key creation failed"
}

func (e ErrKeyCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrKeyWrapFailed is returned when DEK wrapping fails.
type ErrKeyWrapFailed struct {
	KeyID string
	Cause error
}

func (e ErrKeyWrapFailed) Error() string {
	if e.KeyID != "" && e.Cause != nil {
		return fmt.Sprintf("registry: failed to wrap DEK with key %s: %v", e.KeyID, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("registry: DEK wrap failed: %v", e.Cause)
	}
	return "registry: DEK wrap failed"
}

func (e ErrKeyWrapFailed) Unwrap() error {
	return e.Cause
}

// ErrKeyUnwrapFailed is returned when DEK unwrapping fails.
type ErrKeyUnwrapFailed struct {
	KeyID string
	Cause error
}

func (e ErrKeyUnwrapFailed) Error() string {
	if e.KeyID != "" && e.Cause != nil {
		return fmt.Sprintf("registry: failed to unwrap DEK with key %s: %v", e.KeyID, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("registry: DEK unwrap failed: %v", e.Cause)
	}
	return "registry: DEK unwrap failed"
}

func (e ErrKeyUnwrapFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidConfig is returned when registry configuration is invalid.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("registry: invalid configuration for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("registry: invalid configuration: %s", e.Reason)
}

// ErrPCRMismatch is returned when PCR values do not match expected values.
type ErrPCRMismatch struct {
	PCRIndex int
	Expected []byte
	Actual   []byte
}

func (e ErrPCRMismatch) Error() string {
	return fmt.Sprintf("registry: PCR %d mismatch: expected %x, got %x", e.PCRIndex, e.Expected, e.Actual)
}

// ErrAIKNotAllowed is returned when an AIK is not in the allowed list.
type ErrAIKNotAllowed struct {
	AIK string
}

func (e ErrAIKNotAllowed) Error() string {
	return fmt.Sprintf("registry: AIK not in allowed list: %s", e.AIK)
}

// ErrQuicBaaSConnection is returned when connection to QuicBaaS fails.
type ErrQuicBaaSConnection struct {
	Addr  string
	Cause error
}

func (e ErrQuicBaaSConnection) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("registry: failed to connect to QuicBaaS at %s: %v", e.Addr, e.Cause)
	}
	return fmt.Sprintf("registry: failed to connect to QuicBaaS at %s", e.Addr)
}

func (e ErrQuicBaaSConnection) Unwrap() error {
	return e.Cause
}

// ErrSessionExpired is returned when a session has expired.
type ErrSessionExpired struct {
	SessionID string
}

func (e ErrSessionExpired) Error() string {
	if e.SessionID != "" {
		return fmt.Sprintf("registry: session %s has expired", e.SessionID)
	}
	return "registry: session has expired"
}

// ErrSessionNotFound is returned when a session cannot be found.
type ErrSessionNotFound struct {
	SessionID string
}

func (e ErrSessionNotFound) Error() string {
	if e.SessionID != "" {
		return fmt.Sprintf("registry: session %s not found", e.SessionID)
	}
	return "registry: session not found"
}

// ErrInvalidSession is returned when session data is invalid.
type ErrInvalidSession struct {
	Reason string
}

func (e ErrInvalidSession) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("registry: invalid session: %s", e.Reason)
	}
	return "registry: invalid session"
}

// ErrOperationTimeout is returned when an operation times out.
type ErrOperationTimeout struct {
	Operation string
}

func (e ErrOperationTimeout) Error() string {
	return fmt.Sprintf("registry: operation timed out: %s", e.Operation)
}

// ErrDigestMismatch is returned when a content digest does not match expected value.
type ErrDigestMismatch struct {
	Expected string
	Actual   string
}

func (e ErrDigestMismatch) Error() string {
	return fmt.Sprintf("registry: digest mismatch: expected %s, got %s", e.Expected, e.Actual)
}

// ErrNilClient is returned when a required client is nil.
type ErrNilClient struct {
	Client string
}

func (e ErrNilClient) Error() string {
	if e.Client != "" {
		return fmt.Sprintf("registry: %s client is nil", e.Client)
	}
	return "registry: client is nil"
}

// ErrNilContext is returned when a nil context is provided.
type ErrNilContext struct {
	Operation string
}

func (e ErrNilContext) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("registry: nil context provided to %s", e.Operation)
	}
	return "registry: nil context provided"
}

// ErrImageEmpty is returned when an image has no layers.
type ErrImageEmpty struct{}

func (e ErrImageEmpty) Error() string {
	return "registry: image has no layers"
}

// ErrPolicyEvaluationFailed is returned when OPA policy evaluation fails.
type ErrPolicyEvaluationFailed struct {
	Policy string
	Cause  error
}

func (e ErrPolicyEvaluationFailed) Error() string {
	if e.Policy != "" && e.Cause != nil {
		return fmt.Sprintf("registry: policy %s evaluation failed: %v", e.Policy, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("registry: policy evaluation failed: %v", e.Cause)
	}
	return "registry: policy evaluation failed"
}

func (e ErrPolicyEvaluationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidDigest is returned when a digest is invalid.
type ErrInvalidDigest struct {
	Digest string
	Reason string
}

func (e ErrInvalidDigest) Error() string {
	if e.Digest != "" && e.Reason != "" {
		return fmt.Sprintf("registry: invalid digest %s: %s", e.Digest, e.Reason)
	}
	if e.Digest != "" {
		return fmt.Sprintf("registry: invalid digest: %s", e.Digest)
	}
	return "registry: invalid digest"
}

// ErrImageAlreadyExists is returned by Push when the reference is
// already populated and the caller did not request overwrite.
type ErrImageAlreadyExists struct {
	Reference string
}

func (e ErrImageAlreadyExists) Error() string {
	return fmt.Sprintf("registry: image already exists: %s", e.Reference)
}

// ErrStorageNotConfigured is returned by Registry methods when no
// QuicBaaSStorage backend was wired at construction time. The
// daemon's Phase 5 wiring uses registry.WithStorage(...) — if you
// see this in production it means the boot flow forgot to call it.
type ErrStorageNotConfigured struct {
	Op string
}

func (e ErrStorageNotConfigured) Error() string {
	return fmt.Sprintf("registry: storage not configured for %s", e.Op)
}

// ErrEncryptionNotConfigured is returned when a caller requests
// per-image encryption but the encryption pipeline has not been
// wired into the Registry. Encryption + signing land in a follow-up
// after the unencrypted-pipeline ships.
type ErrEncryptionNotConfigured struct {
	Reference string
}

func (e ErrEncryptionNotConfigured) Error() string {
	return fmt.Sprintf("registry: encryption not configured (ref=%s)", e.Reference)
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
