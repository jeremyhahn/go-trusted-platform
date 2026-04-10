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

package vm

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"time"
)

// HashAlgorithm represents a cryptographic hash algorithm.
type HashAlgorithm string

// Supported hash algorithms for TPM operations.
const (
	HashAlgorithmSHA1   HashAlgorithm = "sha1"
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
	HashAlgorithmSHA384 HashAlgorithm = "sha384"
	HashAlgorithmSHA512 HashAlgorithm = "sha512"
)

// String returns the string representation of HashAlgorithm.
func (h HashAlgorithm) String() string {
	return string(h)
}

// IsValid returns true if the hash algorithm is supported.
func (h HashAlgorithm) IsValid() bool {
	switch h {
	case HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA384, HashAlgorithmSHA512:
		return true
	default:
		return false
	}
}

// DigestSize returns the digest size in bytes for the hash algorithm.
func (h HashAlgorithm) DigestSize() int {
	switch h {
	case HashAlgorithmSHA1:
		return 20
	case HashAlgorithmSHA256:
		return 32
	case HashAlgorithmSHA384:
		return 48
	case HashAlgorithmSHA512:
		return 64
	default:
		return 0
	}
}

// VerificationStatus represents the status of a verification operation.
type VerificationStatus string

// Verification status constants.
const (
	VerificationStatusUnknown  VerificationStatus = "unknown"
	VerificationStatusPending  VerificationStatus = "pending"
	VerificationStatusVerified VerificationStatus = "verified"
	VerificationStatusFailed   VerificationStatus = "failed"
)

// String returns the string representation of VerificationStatus.
func (v VerificationStatus) String() string {
	return string(v)
}

// IsValid returns true if the verification status is valid.
func (v VerificationStatus) IsValid() bool {
	switch v {
	case VerificationStatusUnknown, VerificationStatusPending,
		VerificationStatusVerified, VerificationStatusFailed:
		return true
	default:
		return false
	}
}

// VMIdentity represents the identity of a VM, linking it to its host.
// The identity is typically encoded in the vTPM EK certificate subject CN
// with the format: "vm:<vmID>@host:<hostID>"
type VMIdentity struct {
	// VMID is the unique identifier for the virtual machine.
	VMID string

	// HostID is the unique identifier for the host running the VM.
	HostID string

	// EKCertificate is the vTPM Endorsement Key certificate.
	EKCertificate *x509.Certificate

	// EKCertificateChain contains intermediate certificates for chain validation.
	EKCertificateChain []*x509.Certificate
}

// vmIdentityPattern is the regex pattern for parsing VM identity from certificate CN.
var vmIdentityPattern = regexp.MustCompile(`^vm:([^@]+)@host:(.+)$`)

// FormatCN returns the formatted Common Name for the EK certificate.
func (v *VMIdentity) FormatCN() string {
	return fmt.Sprintf("vm:%s@host:%s", v.VMID, v.HostID)
}

// ParseCN parses a VM identity from a certificate Common Name.
// Expected format: "vm:<vmID>@host:<hostID>"
func ParseCN(cn string) (*VMIdentity, error) {
	matches := vmIdentityPattern.FindStringSubmatch(cn)
	if matches == nil || len(matches) != 3 {
		return nil, ErrInvalidVMIdentity{
			Reason: "CN format must be 'vm:<vmID>@host:<hostID>'",
		}
	}

	vmID := matches[1]
	hostID := matches[2]

	if vmID == "" {
		return nil, ErrInvalidVMIdentity{
			HostID: hostID,
			Reason: "vmID cannot be empty",
		}
	}

	if hostID == "" {
		return nil, ErrInvalidVMIdentity{
			VMID:   vmID,
			Reason: "hostID cannot be empty",
		}
	}

	return &VMIdentity{
		VMID:   vmID,
		HostID: hostID,
	}, nil
}

// Validate validates the VM identity fields.
func (v *VMIdentity) Validate() error {
	if v.VMID == "" {
		return ErrInvalidVMIdentity{
			HostID: v.HostID,
			Reason: "vmID cannot be empty",
		}
	}

	if v.HostID == "" {
		return ErrInvalidVMIdentity{
			VMID:   v.VMID,
			Reason: "hostID cannot be empty",
		}
	}

	return nil
}

// PCRValue represents a single PCR index and its value.
type PCRValue struct {
	// Index is the PCR index (0-23).
	Index int

	// Value is the PCR digest value.
	Value []byte

	// Algorithm is the hash algorithm used for this PCR bank.
	Algorithm HashAlgorithm
}

// VMQuote represents a TPM quote from a VM's vTPM.
type VMQuote struct {
	// QuoteData is the raw TPM quote structure (TPMS_ATTEST).
	QuoteData []byte

	// Signature is the AIK/AK signature over the quote data.
	Signature []byte

	// SignatureAlgorithm is the algorithm used for signing.
	SignatureAlgorithm string

	// PCRs contains the PCR values included in the quote.
	PCRs []PCRValue

	// PCRDigest is the hash of the PCR values.
	PCRDigest []byte

	// Nonce is the anti-replay nonce included in the quote.
	Nonce []byte

	// Timestamp is when the quote was generated.
	Timestamp time.Time

	// AIKPublicKey is the public key of the AIK/AK used for signing.
	AIKPublicKey []byte

	// FirmwareVersion is the TPM firmware version (if available).
	FirmwareVersion string

	// HashAlgorithm is the hash algorithm used for the quote.
	HashAlgorithm HashAlgorithm
}

// Validate validates the VMQuote fields.
func (q *VMQuote) Validate() error {
	if len(q.QuoteData) == 0 {
		return ErrQuoteVerificationFailed{Reason: "quote data is empty"}
	}

	if len(q.Signature) == 0 {
		return ErrQuoteVerificationFailed{Reason: "signature is empty"}
	}

	if len(q.PCRs) == 0 {
		return ErrQuoteVerificationFailed{Reason: "no PCR values in quote"}
	}

	if len(q.Nonce) == 0 {
		return ErrQuoteVerificationFailed{Reason: "nonce is empty"}
	}

	if !q.HashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: q.HashAlgorithm.String()}
	}

	return nil
}

// VMAttestation represents the full attestation result for a VM.
type VMAttestation struct {
	// Identity contains the VM identity information.
	Identity *VMIdentity

	// Quote is the TPM quote from the vTPM.
	Quote *VMQuote

	// VerificationResult contains the verification outcome.
	VerificationResult *VerificationResult

	// Timestamp is when the attestation was performed.
	Timestamp time.Time

	// AttestationID is a unique identifier for this attestation.
	AttestationID string

	// WorkloadPCR is the PCR value from the WorkloadPCR index (workload chain).
	// The PCR index is configurable (default: 14).
	WorkloadPCR []byte

	// Metadata contains additional attestation metadata.
	Metadata map[string]string
}

// Validate validates the VMAttestation fields.
func (a *VMAttestation) Validate() error {
	if a.Identity == nil {
		return ErrInvalidVMIdentity{Reason: "identity is nil"}
	}

	if err := a.Identity.Validate(); err != nil {
		return err
	}

	if a.Quote == nil {
		return ErrQuoteVerificationFailed{Reason: "quote is nil"}
	}

	if err := a.Quote.Validate(); err != nil {
		return err
	}

	return nil
}

// IsVerified returns true if the attestation has been successfully verified.
func (a *VMAttestation) IsVerified() bool {
	if a.VerificationResult == nil {
		return false
	}
	return a.VerificationResult.Status == VerificationStatusVerified
}

// VerificationResult represents the outcome of quote verification.
type VerificationResult struct {
	// Status indicates the overall verification status.
	Status VerificationStatus

	// SignatureValid indicates if the quote signature is valid.
	SignatureValid bool

	// CertificateChainValid indicates if the EK certificate chain is valid.
	CertificateChainValid bool

	// PCRsValid indicates if all PCR values match expected values.
	PCRsValid bool

	// NonceValid indicates if the nonce matches the expected value.
	NonceValid bool

	// HostBindingValid indicates if the VM-to-host binding is valid.
	HostBindingValid bool

	// TimestampValid indicates if the quote timestamp is within acceptable range.
	TimestampValid bool

	// VerifiedAt is when the verification was performed.
	VerifiedAt time.Time

	// Errors contains any errors encountered during verification.
	Errors []string

	// PCRMismatches contains details about any PCR mismatches.
	PCRMismatches []PCRMismatchDetail
}

// PCRMismatchDetail provides details about a PCR mismatch.
type PCRMismatchDetail struct {
	// Index is the PCR index that mismatched.
	Index int

	// Expected is the expected PCR value.
	Expected []byte

	// Actual is the actual PCR value from the quote.
	Actual []byte
}

// AddError adds an error message to the verification result.
func (v *VerificationResult) AddError(err string) {
	v.Errors = append(v.Errors, err)
}

// HasErrors returns true if there are any verification errors.
func (v *VerificationResult) HasErrors() bool {
	return len(v.Errors) > 0
}

// QuoteRequest represents a request to generate a TPM quote.
type QuoteRequest struct {
	// Nonce is the anti-replay nonce to include in the quote.
	Nonce []byte

	// PCRIndices specifies which PCRs to include in the quote.
	PCRIndices []int

	// HashAlgorithm specifies the hash algorithm for the quote.
	HashAlgorithm HashAlgorithm
}

// Validate validates the QuoteRequest fields.
func (r *QuoteRequest) Validate() error {
	if len(r.Nonce) == 0 {
		return ErrInvalidConfig{Field: "Nonce", Reason: "nonce cannot be empty"}
	}

	if len(r.PCRIndices) == 0 {
		return ErrInvalidConfig{Field: "PCRIndices", Reason: "PCR indices cannot be empty"}
	}

	for _, idx := range r.PCRIndices {
		if idx < 0 || idx > 23 {
			return ErrInvalidConfig{
				Field:  "PCRIndices",
				Reason: fmt.Sprintf("PCR index %d out of range (0-23)", idx),
			}
		}
	}

	if !r.HashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: r.HashAlgorithm.String()}
	}

	return nil
}

// VerifyRequest represents a request to verify a TPM quote.
type VerifyRequest struct {
	// Quote is the quote to verify.
	Quote *VMQuote

	// Identity is the expected VM identity.
	Identity *VMIdentity

	// ExpectedNonce is the nonce that should be in the quote.
	ExpectedNonce []byte

	// ExpectedPCRs contains the expected PCR values.
	ExpectedPCRs map[int][]byte

	// PlatformCACert is the Platform CA certificate for chain validation.
	PlatformCACert *x509.Certificate

	// MaxQuoteAge is the maximum age of a quote in seconds (0 = no limit).
	MaxQuoteAge int64

	// ExpectedHostID is the expected host ID for binding validation (optional).
	ExpectedHostID string
}

// Validate validates the VerifyRequest fields.
func (r *VerifyRequest) Validate() error {
	if r.Quote == nil {
		return ErrInvalidConfig{Field: "Quote", Reason: "quote cannot be nil"}
	}

	if r.Identity == nil {
		return ErrInvalidConfig{Field: "Identity", Reason: "identity cannot be nil"}
	}

	if len(r.ExpectedNonce) == 0 {
		return ErrInvalidConfig{Field: "ExpectedNonce", Reason: "expected nonce cannot be empty"}
	}

	if r.PlatformCACert == nil {
		return ErrInvalidConfig{Field: "PlatformCACert", Reason: "Platform CA certificate cannot be nil"}
	}

	return nil
}

// AttestorConfig contains configuration for the VMAttestor.
type AttestorConfig struct {
	// VTPMDevicePath is the path to the vTPM device.
	VTPMDevicePath string

	// AIKHandle is the TPM handle for the AIK/AK.
	AIKHandle uint32

	// DefaultHashAlgorithm is the default hash algorithm for quotes.
	DefaultHashAlgorithm HashAlgorithm

	// DefaultPCRIndices are the default PCRs to include in quotes.
	DefaultPCRIndices []int

	// IncludeWorkloadPCR includes the WorkloadPCR (workload chain) in quotes.
	IncludeWorkloadPCR bool

	// WorkloadPCRIndex is the PCR index used for workload attestation.
	// Default: 14 (configurable via platform config).
	WorkloadPCRIndex int
}

// DefaultWorkloadPCRIndex is the default PCR index for workload attestation.
const DefaultWorkloadPCRIndex = 14

// GetWorkloadPCRIndex returns the configured WorkloadPCR index, or the default if not set.
func (c *AttestorConfig) GetWorkloadPCRIndex() int {
	if c == nil || c.WorkloadPCRIndex == 0 {
		return DefaultWorkloadPCRIndex
	}
	return c.WorkloadPCRIndex
}

// Validate validates the AttestorConfig fields.
func (c *AttestorConfig) Validate() error {
	if c.VTPMDevicePath == "" {
		return ErrInvalidConfig{Field: "VTPMDevicePath", Reason: "vTPM device path cannot be empty"}
	}

	if !c.DefaultHashAlgorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: c.DefaultHashAlgorithm.String()}
	}

	// Validate WorkloadPCRIndex if set
	if c.WorkloadPCRIndex != 0 && (c.WorkloadPCRIndex < 0 || c.WorkloadPCRIndex > 23) {
		return ErrInvalidConfig{
			Field:  "WorkloadPCRIndex",
			Reason: "WorkloadPCR index must be between 0 and 23",
		}
	}

	return nil
}

// VerifierConfig contains configuration for the VMVerifier.
type VerifierConfig struct {
	// PlatformCACert is the Platform CA certificate for chain validation.
	PlatformCACert *x509.Certificate

	// TrustedRoots contains additional trusted root certificates.
	TrustedRoots []*x509.Certificate

	// MaxQuoteAge is the maximum age of a quote in seconds (0 = no limit).
	MaxQuoteAge int64

	// RequireHostBinding requires VM-to-host binding validation.
	RequireHostBinding bool

	// AllowedHostIDs is a list of allowed host IDs (empty = allow all).
	AllowedHostIDs []string
}

// Validate validates the VerifierConfig fields.
func (c *VerifierConfig) Validate() error {
	if c.PlatformCACert == nil {
		return ErrInvalidConfig{Field: "PlatformCACert", Reason: "Platform CA certificate cannot be nil"}
	}

	if c.MaxQuoteAge < 0 {
		return ErrInvalidConfig{Field: "MaxQuoteAge", Reason: "max quote age cannot be negative"}
	}

	return nil
}
