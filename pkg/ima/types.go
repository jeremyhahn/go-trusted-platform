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

// Package ima provides functionality for reading and verifying
// Linux Integrity Measurement Architecture (IMA) event logs.
package ima

import (
	"errors"
	"time"
)

var (
	// ErrNotAvailable is returned when IMA is not available on the system
	ErrNotAvailable = errors.New("IMA is not available on this system")

	// ErrSecurityFSNotMounted is returned when securityfs is not mounted
	ErrSecurityFSNotMounted = errors.New("securityfs is not mounted")

	// ErrInvalidEventFormat is returned when an IMA event has invalid format
	ErrInvalidEventFormat = errors.New("invalid IMA event format")

	// ErrHashMismatch is returned when a measurement hash doesn't match expected value
	ErrHashMismatch = errors.New("measurement hash mismatch")

	// ErrPolicyViolation is returned when an IMA policy violation is detected
	ErrPolicyViolation = errors.New("IMA policy violation detected")

	// ErrAppraisalFailure is returned when IMA appraisal fails
	ErrAppraisalFailure = errors.New("IMA appraisal failure")

	// ErrKeyNotLoaded is returned when the IMA signing key is not loaded
	ErrKeyNotLoaded = errors.New("IMA signing key not loaded")

	// ErrTPMNotAvailable is returned when TPM is not available or accessible
	ErrTPMNotAvailable = errors.New("TPM device not available")

	// ErrPCRReadFailed is returned when reading PCR value fails
	ErrPCRReadFailed = errors.New("failed to read PCR value")

	// ErrPCRMismatch is returned when PCR value doesn't match computed value
	ErrPCRMismatch = errors.New("PCR value mismatch")

	// ErrInvalidPCRBank is returned when an invalid PCR bank is specified
	ErrInvalidPCRBank = errors.New("invalid PCR bank")
)

// DefaultSecurityFSPath is the default mount point for securityfs
const DefaultSecurityFSPath = "/sys/kernel/security"

// IMAPath is the path to IMA interfaces within securityfs
const IMAPath = "/sys/kernel/security/ima"

// DefaultTPMSysPath is the default sysfs path for TPM devices
const DefaultTPMSysPath = "/sys/class/tpm/tpm0"

// EventPaths contains paths to IMA event interfaces
var EventPaths = struct {
	// ASCIIRuntime is the ASCII format runtime measurement log
	ASCIIRuntime string
	// BinaryRuntime is the binary format runtime measurement log
	BinaryRuntime string
	// Policy is the current IMA policy
	Policy string
	// Violations is the IMA violations log (appraisal mode)
	Violations string
}{
	ASCIIRuntime:  "/sys/kernel/security/ima/ascii_runtime_measurements",
	BinaryRuntime: "/sys/kernel/security/ima/binary_runtime_measurements",
	Policy:        "/sys/kernel/security/ima/policy",
	Violations:    "/sys/kernel/security/ima/violations",
}

// TPMPaths contains paths to TPM sysfs interfaces
var TPMPaths = struct {
	// TPM0 is the default TPM device path
	TPM0 string
	// PCRS is the PCR banks directory name format (pcr-<algorithm>)
	PCRS string
}{
	TPM0: "/sys/class/tpm/tpm0",
	PCRS: "pcr-%s", // Format string for PCR bank directories
}

// Event represents a single IMA measurement event
type Event struct {
	// PCR is the PCR index where the measurement was extended
	PCR int

	// TemplateHash is the hash of the template data
	TemplateHash []byte

	// TemplateName is the name of the IMA template (e.g., "ima-ng", "ima-sig")
	TemplateName string

	// FileHash is the hash of the measured file/data
	FileHash []byte

	// HashAlgorithm is the hash algorithm used (e.g., "sha256", "sha1")
	HashAlgorithm string

	// FilePath is the path to the measured file
	FilePath string

	// Signature contains the file signature (for ima-sig template)
	Signature []byte

	// UID is the user ID of the process that triggered the measurement (if available)
	UID int

	// EventType is the type of event (e.g., "ima_file_hash", "ima_xattr")
	EventType string

	// Timestamp is when the event was recorded (if available)
	Timestamp time.Time

	// RawLine is the original line from the event log
	RawLine string
}

// EventLog represents a parsed IMA event log
type EventLog struct {
	// Events is the list of IMA events
	Events []*Event

	// TotalCount is the total number of events
	TotalCount int

	// UniqueFiles is the number of unique file paths measured
	UniqueFiles int

	// ViolationCount is the number of policy violations
	ViolationCount int

	// ParseErrors is the number of events that failed to parse
	ParseErrors int

	// ParsedAt is when the event log was parsed
	ParsedAt time.Time
}

// Status represents the current IMA status
type Status struct {
	// Available indicates if IMA is available on the system
	Available bool

	// Enabled indicates if IMA is enabled
	Enabled bool

	// PolicyLoaded indicates if an IMA policy is loaded
	PolicyLoaded bool

	// HashAlgorithm is the configured hash algorithm
	HashAlgorithm string

	// PolicyType is the type of policy loaded (tcb, appraise_tcb, etc.)
	PolicyType string

	// AppraiseMode is the appraise mode (off, log, enforce, fix)
	AppraiseMode string

	// EVMEnabled indicates if EVM (Extended Verification Module) is enabled
	EVMEnabled bool

	// SigningKeyLoaded indicates if the signing key is loaded
	SigningKeyLoaded bool

	// MeasurementCount is the number of measurements in the log
	MeasurementCount int

	// ViolationCount is the number of violations detected
	ViolationCount int

	// PCR10Value is the current value of PCR 10
	PCR10Value []byte

	// TPMAvailable indicates if TPM is available for PCR verification
	TPMAvailable bool

	// AvailablePCRBanks lists the PCR banks available on the TPM
	AvailablePCRBanks []string
}

// PolicyRule represents an IMA policy rule
type PolicyRule struct {
	// Action is the rule action (measure, appraise, audit, hash, dont_measure, etc.)
	Action string

	// Condition is the condition for applying the rule
	Condition string

	// Func is the function type (FILE_CHECK, MMAP_CHECK, BPRM_CHECK, etc.)
	Func string

	// Mask is the access mask (MAY_READ, MAY_WRITE, MAY_EXEC, etc.)
	Mask string

	// PCR is the PCR to extend
	PCR int

	// Template is the template to use (ima-ng, ima-sig, etc.)
	Template string

	// RawRule is the original rule string
	RawRule string
}

// Policy represents the loaded IMA policy
type Policy struct {
	// Rules is the list of policy rules
	Rules []*PolicyRule

	// RuleCount is the total number of rules
	RuleCount int

	// LoadedAt is when the policy was loaded
	LoadedAt time.Time
}

// VerificationResult represents the result of IMA verification
type VerificationResult struct {
	// Passed indicates if verification passed
	Passed bool

	// TotalMeasurements is the total number of measurements checked
	TotalMeasurements int

	// ValidMeasurements is the number of valid measurements
	ValidMeasurements int

	// InvalidMeasurements is the number of invalid measurements
	InvalidMeasurements int

	// MissingFiles is a list of files that should be measured but weren't
	MissingFiles []string

	// UnexpectedFiles is a list of files that were measured but shouldn't be
	UnexpectedFiles []string

	// ViolationFiles is a list of files that caused policy violations
	ViolationFiles []string

	// Errors is a list of verification errors
	Errors []error

	// Duration is how long verification took
	Duration time.Duration

	// VerifiedAt is when verification was performed
	VerifiedAt time.Time

	// PCR10Verified indicates if PCR 10 was verified against TPM
	PCR10Verified bool

	// PCR10Bank is the PCR bank used for verification (if PCR10Verified is true)
	PCR10Bank string
}

// Statistics provides IMA measurement statistics
type Statistics struct {
	// TotalEvents is the total number of events in the log
	TotalEvents int

	// UniqueFiles is the number of unique file paths
	UniqueFiles int

	// FilesByHashAlg is a map of hash algorithm to file count
	FilesByHashAlg map[string]int

	// FilesByTemplate is a map of template name to file count
	FilesByTemplate map[string]int

	// FilesByAction is a map of action to file count
	FilesByAction map[string]int

	// TopPaths is the list of most frequently measured paths
	TopPaths []string

	// ViolationCount is the number of violations
	ViolationCount int

	// CollectedAt is when statistics were collected
	CollectedAt time.Time
}
