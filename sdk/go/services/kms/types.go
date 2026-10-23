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

package kms

// KeyAlgorithm represents a cryptographic key algorithm as a string constant.
type KeyAlgorithm string

const (
	KeyAlgorithmUnspecified  KeyAlgorithm = "UNSPECIFIED"
	KeyAlgorithmAES128       KeyAlgorithm = "AES-128"
	KeyAlgorithmAES192       KeyAlgorithm = "AES-192"
	KeyAlgorithmAES256       KeyAlgorithm = "AES-256"
	KeyAlgorithmChaCha20Poly KeyAlgorithm = "ChaCha20-Poly1305"
	KeyAlgorithmRSA2048      KeyAlgorithm = "RSA-2048"
	KeyAlgorithmRSA3072      KeyAlgorithm = "RSA-3072"
	KeyAlgorithmRSA4096      KeyAlgorithm = "RSA-4096"
	KeyAlgorithmECDSAP256    KeyAlgorithm = "ECDSA-P256"
	KeyAlgorithmECDSAP384    KeyAlgorithm = "ECDSA-P384"
	KeyAlgorithmECDSAP521    KeyAlgorithm = "ECDSA-P521"
	KeyAlgorithmED25519      KeyAlgorithm = "Ed25519"
	KeyAlgorithmDilithium2   KeyAlgorithm = "Dilithium2"
	KeyAlgorithmDilithium3   KeyAlgorithm = "Dilithium3"
	KeyAlgorithmDilithium5   KeyAlgorithm = "Dilithium5"
	KeyAlgorithmHMACSHA256   KeyAlgorithm = "HMAC-SHA256"
	KeyAlgorithmHMACSHA384   KeyAlgorithm = "HMAC-SHA384"
	KeyAlgorithmHMACSHA512   KeyAlgorithm = "HMAC-SHA512"
)

// KeyStatus represents the lifecycle status of a key.
type KeyStatus string

const (
	KeyStatusUnspecified     KeyStatus = "UNKNOWN"
	KeyStatusEnabled         KeyStatus = "ENABLED"
	KeyStatusDisabled        KeyStatus = "DISABLED"
	KeyStatusPendingDeletion KeyStatus = "PENDING DELETION"
	KeyStatusDestroyed       KeyStatus = "DESTROYED"
	KeyStatusPendingImport   KeyStatus = "PENDING IMPORT"
)

// KeyUsage represents the intended usage of a key.
type KeyUsage string

const (
	KeyUsageUnspecified KeyUsage = "unspecified"
	KeyUsageEncrypt     KeyUsage = "encrypt"
	KeyUsageDecrypt     KeyUsage = "decrypt"
	KeyUsageSign        KeyUsage = "sign"
	KeyUsageVerify      KeyUsage = "verify"
	KeyUsageWrap        KeyUsage = "wrap"
	KeyUsageUnwrap      KeyUsage = "unwrap"
	KeyUsageDerive      KeyUsage = "derive"
	KeyUsageHMAC        KeyUsage = "hmac"
)

// HashAlgorithm represents a hash algorithm.
type HashAlgorithm string

const (
	HashAlgorithmUnspecified HashAlgorithm = "UNSPECIFIED"
	HashAlgorithmSHA1        HashAlgorithm = "SHA-1"
	HashAlgorithmSHA256      HashAlgorithm = "SHA-256"
	HashAlgorithmSHA384      HashAlgorithm = "SHA-384"
	HashAlgorithmSHA512      HashAlgorithm = "SHA-512"
	HashAlgorithmSHA3256     HashAlgorithm = "SHA3-256"
	HashAlgorithmSHA3384     HashAlgorithm = "SHA3-384"
	HashAlgorithmSHA3512     HashAlgorithm = "SHA3-512"
)

// KeyInfo represents basic key information.
type KeyInfo struct {
	KeyID     string       `json:"key_id" yaml:"key_id"`
	Version   uint64       `json:"version" yaml:"version"`
	Algorithm KeyAlgorithm `json:"algorithm" yaml:"algorithm"`
	Status    KeyStatus    `json:"status" yaml:"status"`
	CreatedAt int64        `json:"created_at" yaml:"created_at"`
}

// KeyMetadata represents key metadata.
type KeyMetadata struct {
	Name               string     `json:"name,omitempty" yaml:"name,omitempty"`
	Description        string     `json:"description,omitempty" yaml:"description,omitempty"`
	Exportable         bool       `json:"exportable" yaml:"exportable"`
	DeletionProtection bool       `json:"deletion_protection" yaml:"deletion_protection"`
	Owner              string     `json:"owner,omitempty" yaml:"owner,omitempty"`
	UpdatedAt          int64      `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
	LastUsedAt         int64      `json:"last_used_at,omitempty" yaml:"last_used_at,omitempty"`
	Usage              []KeyUsage `json:"usage,omitempty" yaml:"usage,omitempty"`
}

// GenerateKeyParams holds parameters for key generation.
type GenerateKeyParams struct {
	// KeyID names the key; the generate request carries it as its name.
	KeyID              string
	Algorithm          KeyAlgorithm
	Usages             []KeyUsage
	Exportable         bool
	DeletionProtection bool
	// Name is a display name, stored as key metadata, never the key ID.
	Name        string
	Description string
	Owner       string
}

// GenerateKeyResult holds the result of key generation.
type GenerateKeyResult struct {
	Key      *KeyInfo     `json:"key" yaml:"key"`
	Metadata *KeyMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// GetKeyResult holds the result of getting a key.
type GetKeyResult struct {
	Key      *KeyInfo     `json:"key" yaml:"key"`
	Metadata *KeyMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// ListKeysResult holds the result of listing keys.
type ListKeysResult struct {
	Keys       []*KeyInfo `json:"keys" yaml:"keys"`
	TotalCount int32      `json:"total_count" yaml:"total_count"`
	HasMore    bool       `json:"has_more" yaml:"has_more"`
	NextCursor string     `json:"next_cursor,omitempty" yaml:"next_cursor,omitempty"`
}

// DeleteKeyResult holds the result of key deletion.
type DeleteKeyResult struct {
	KeyID        string    `json:"key_id" yaml:"key_id"`
	KeyStatus    KeyStatus `json:"key_status" yaml:"key_status"`
	DeletionDate int64     `json:"deletion_date,omitempty" yaml:"deletion_date,omitempty"`
}

// RotateKeyResult holds the result of key rotation.
type RotateKeyResult struct {
	KeyID      string `json:"key_id" yaml:"key_id"`
	OldVersion uint64 `json:"old_version" yaml:"old_version"`
	NewVersion uint64 `json:"new_version" yaml:"new_version"`
	Timestamp  int64  `json:"timestamp" yaml:"timestamp"`
}

// EncryptResult holds the result of an encryption operation.
type EncryptResult struct {
	KeyID      string `json:"key_id" yaml:"key_id"`
	KeyVersion uint64 `json:"key_version" yaml:"key_version"`
	Ciphertext []byte `json:"ciphertext" yaml:"ciphertext"`
	Nonce      []byte `json:"nonce" yaml:"nonce"`
	Timestamp  int64  `json:"timestamp" yaml:"timestamp"`
}

// DecryptResult holds the result of a decryption operation.
type DecryptResult struct {
	KeyID      string `json:"key_id" yaml:"key_id"`
	KeyVersion uint64 `json:"key_version" yaml:"key_version"`
	Plaintext  []byte `json:"plaintext" yaml:"plaintext"`
	Timestamp  int64  `json:"timestamp" yaml:"timestamp"`
}

// SignResult holds the result of a signing operation.
type SignResult struct {
	KeyID         string        `json:"key_id" yaml:"key_id"`
	KeyVersion    uint64        `json:"key_version" yaml:"key_version"`
	Signature     []byte        `json:"signature" yaml:"signature"`
	HashAlgorithm HashAlgorithm `json:"hash_algorithm" yaml:"hash_algorithm"`
	Timestamp     int64         `json:"timestamp" yaml:"timestamp"`
}

// VerifyResult holds the result of a verification operation.
type VerifyResult struct {
	KeyID      string `json:"key_id" yaml:"key_id"`
	KeyVersion uint64 `json:"key_version" yaml:"key_version"`
	Valid      bool   `json:"valid" yaml:"valid"`
	Timestamp  int64  `json:"timestamp" yaml:"timestamp"`
}

// HashResult holds the result of a hash computation.
type HashResult struct {
	Hash      []byte        `json:"hash" yaml:"hash"`
	Algorithm HashAlgorithm `json:"algorithm" yaml:"algorithm"`
	Timestamp int64         `json:"timestamp" yaml:"timestamp"`
}

// HMACResult holds the result of an HMAC operation.
type HMACResult struct {
	KeyID         string        `json:"key_id" yaml:"key_id"`
	KeyVersion    uint64        `json:"key_version" yaml:"key_version"`
	HMAC          []byte        `json:"hmac" yaml:"hmac"`
	HashAlgorithm HashAlgorithm `json:"hash_algorithm" yaml:"hash_algorithm"`
	Timestamp     int64         `json:"timestamp" yaml:"timestamp"`
}

// VerifyHMACResult holds the result of an HMAC verification.
type VerifyHMACResult struct {
	KeyID      string `json:"key_id" yaml:"key_id"`
	KeyVersion uint64 `json:"key_version" yaml:"key_version"`
	Valid      bool   `json:"valid" yaml:"valid"`
	Timestamp  int64  `json:"timestamp" yaml:"timestamp"`
}

// GenerateRandomResult holds the result of random byte generation.
type GenerateRandomResult struct {
	RandomBytes []byte `json:"random_bytes" yaml:"random_bytes"`
	Timestamp   int64  `json:"timestamp" yaml:"timestamp"`
}

// GenerateDataKeyResult holds the result of data key generation.
type GenerateDataKeyResult struct {
	KeyID        string `json:"key_id" yaml:"key_id"`
	PlaintextKey []byte `json:"plaintext_key" yaml:"plaintext_key"`
	EncryptedKey []byte `json:"encrypted_key" yaml:"encrypted_key"`
	Timestamp    int64  `json:"timestamp" yaml:"timestamp"`
}

// GenerateWrappedDataKeyResult holds the result of wrapped data key generation.
type GenerateWrappedDataKeyResult struct {
	WrappingKeyID string `json:"wrapping_key_id" yaml:"wrapping_key_id"`
	WrappedKey    []byte `json:"wrapped_key" yaml:"wrapped_key"`
	Timestamp     int64  `json:"timestamp" yaml:"timestamp"`
}

// RewrapResult holds the result of a rewrap operation.
type RewrapResult struct {
	KeyID         string `json:"key_id" yaml:"key_id"`
	SourceVersion uint64 `json:"source_version" yaml:"source_version"`
	TargetVersion uint64 `json:"target_version" yaml:"target_version"`
	Ciphertext    []byte `json:"ciphertext" yaml:"ciphertext"`
	Nonce         []byte `json:"nonce" yaml:"nonce"`
	Timestamp     int64  `json:"timestamp" yaml:"timestamp"`
}

// BackendStatusResult holds the result of a backend status query.
type BackendStatusResult struct {
	BackendStatus string          `json:"backend_status" yaml:"backend_status"`
	BackendType   string          `json:"backend_type" yaml:"backend_type"`
	Device        string          `json:"device,omitempty" yaml:"device,omitempty"`
	Region        string          `json:"region,omitempty" yaml:"region,omitempty"`
	KeyID         string          `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	PcrBanks      []string        `json:"pcr_banks,omitempty" yaml:"pcr_banks,omitempty"`
	PcrRegisters  []int32         `json:"pcr_registers,omitempty" yaml:"pcr_registers,omitempty"`
	Capabilities  map[string]bool `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Timestamp     int64           `json:"timestamp" yaml:"timestamp"`
}

// BatchEncryptItemInput represents an input item for batch encryption.
type BatchEncryptItemInput struct {
	ItemID    string
	Plaintext []byte
	Context   []byte
	Nonce     []byte
}

// BatchEncryptItemResult represents a result item from batch encryption.
type BatchEncryptItemResult struct {
	ItemID     string `json:"item_id" yaml:"item_id"`
	Success    bool   `json:"success" yaml:"success"`
	Ciphertext []byte `json:"ciphertext,omitempty" yaml:"ciphertext,omitempty"`
	Nonce      []byte `json:"nonce,omitempty" yaml:"nonce,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty" yaml:"key_version,omitempty"`
	Message    string `json:"message,omitempty" yaml:"message,omitempty"`
}

// BatchEncryptResult holds the result of a batch encryption operation.
type BatchEncryptResult struct {
	KeyID        string                    `json:"key_id" yaml:"key_id"`
	SuccessCount int32                     `json:"success_count" yaml:"success_count"`
	FailureCount int32                     `json:"failure_count" yaml:"failure_count"`
	Results      []*BatchEncryptItemResult `json:"results" yaml:"results"`
	Timestamp    int64                     `json:"timestamp" yaml:"timestamp"`
}

// BatchDecryptItemInput represents an input item for batch decryption.
type BatchDecryptItemInput struct {
	ItemID     string
	Ciphertext []byte
	Context    []byte
	Nonce      []byte
	KeyVersion uint64
}

// BatchDecryptItemResult represents a result item from batch decryption.
type BatchDecryptItemResult struct {
	ItemID     string `json:"item_id" yaml:"item_id"`
	Success    bool   `json:"success" yaml:"success"`
	Plaintext  []byte `json:"plaintext,omitempty" yaml:"plaintext,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty" yaml:"key_version,omitempty"`
	Message    string `json:"message,omitempty" yaml:"message,omitempty"`
}

// BatchDecryptResult holds the result of a batch decryption operation.
type BatchDecryptResult struct {
	KeyID        string                    `json:"key_id" yaml:"key_id"`
	SuccessCount int32                     `json:"success_count" yaml:"success_count"`
	FailureCount int32                     `json:"failure_count" yaml:"failure_count"`
	Results      []*BatchDecryptItemResult `json:"results" yaml:"results"`
	Timestamp    int64                     `json:"timestamp" yaml:"timestamp"`
}
