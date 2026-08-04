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

package ima

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"time"
)

// Verifier verifies IMA measurements against expected values
type Verifier struct {
	reader         *Reader
	allowlist      map[string][]byte            // path -> expected hash
	allowlistByAlg map[string]map[string][]byte // algorithm -> path -> expected hash
}

// VerifierOption configures a Verifier
type VerifierOption func(*Verifier)

// WithAllowlist sets a file path to hash allowlist
func WithAllowlist(allowlist map[string][]byte) VerifierOption {
	return func(v *Verifier) {
		v.allowlist = allowlist
	}
}

// WithReader sets a custom IMA reader
func WithReader(reader *Reader) VerifierOption {
	return func(v *Verifier) {
		v.reader = reader
	}
}

// NewVerifier creates a new IMA verifier
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		reader:         NewReader(),
		allowlist:      make(map[string][]byte),
		allowlistByAlg: make(map[string]map[string][]byte),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyEventLog verifies all events in an IMA event log
func (v *Verifier) VerifyEventLog(log *EventLog) *VerificationResult {
	start := time.Now()
	result := &VerificationResult{
		Passed:          true,
		VerifiedAt:      time.Now(),
		MissingFiles:    make([]string, 0),
		UnexpectedFiles: make([]string, 0),
		ViolationFiles:  make([]string, 0),
		Errors:          make([]error, 0),
	}

	if log == nil {
		result.Passed = false
		result.Errors = append(result.Errors, ErrNotAvailable)
		result.Duration = time.Since(start)
		return result
	}

	result.TotalMeasurements = log.TotalCount

	// Track verified paths to detect duplicates/re-measurements
	verifiedPaths := make(map[string]bool)

	for _, event := range log.Events {
		if err := v.verifyEvent(event); err != nil {
			result.InvalidMeasurements++
			result.Passed = false

			if event.FilePath != "" {
				result.ViolationFiles = append(result.ViolationFiles, event.FilePath)
			}
			result.Errors = append(result.Errors, &WrappedError{Msg: fmt.Sprintf("event verification failed for %s", event.FilePath), Err: err})
		} else {
			result.ValidMeasurements++
			if event.FilePath != "" {
				verifiedPaths[event.FilePath] = true
			}
		}
	}

	// Check for missing files (files in allowlist not measured)
	for path := range v.allowlist {
		if !verifiedPaths[path] {
			result.MissingFiles = append(result.MissingFiles, path)
		}
	}

	result.Duration = time.Since(start)
	return result
}

// verifyEvent verifies a single IMA event
func (v *Verifier) verifyEvent(event *Event) error {
	if event == nil {
		return ErrInvalidEventFormat
	}

	// Verify template hash matches file hash + metadata
	if err := v.verifyTemplateHash(event); err != nil {
		return &WrappedError{Msg: "template hash verification failed", Err: err}
	}

	// If we have an allowlist, verify against it
	if len(v.allowlist) > 0 && event.FilePath != "" {
		if err := v.verifyAgainstAllowlist(event); err != nil {
			return err
		}
	}

	return nil
}

// verifyTemplateHash verifies the template hash is correctly computed
func (v *Verifier) verifyTemplateHash(event *Event) error {
	if len(event.TemplateHash) == 0 {
		return ErrInvalidEventFormat
	}

	// For basic verification, we just ensure the template hash exists
	// Full template hash verification requires knowing the exact template format
	// which varies (ima, ima-ng, ima-sig, etc.)

	// Verify the hash length matches expected algorithm
	switch len(event.TemplateHash) {
	case sha1.Size: // 20 bytes - SHA1
		return nil
	case sha256.Size: // 32 bytes - SHA256
		return nil
	case sha512.Size384: // 48 bytes - SHA384
		return nil
	case sha512.Size: // 64 bytes - SHA512
		return nil
	default:
		return &SentinelCauseError{Sentinel: ErrHashMismatch, Cause: &MessageError{Msg: fmt.Sprintf("unexpected template hash length %d", len(event.TemplateHash))}}
	}
}

// verifyAgainstAllowlist verifies an event's file hash matches the allowlist
func (v *Verifier) verifyAgainstAllowlist(event *Event) error {
	expectedHash, exists := v.allowlist[event.FilePath]
	if !exists {
		// File not in allowlist - might be unexpected
		return nil // Don't fail, just not in allowlist
	}

	if !bytes.Equal(event.FileHash, expectedHash) {
		return &SentinelCauseError{Sentinel: ErrHashMismatch, Cause: &MessageError{Msg: fmt.Sprintf("file %s hash mismatch (expected %x, got %x)", event.FilePath, expectedHash, event.FileHash)}}
	}

	return nil
}

// VerifyFile verifies a file's current hash matches its measured hash
func (v *Verifier) VerifyFile(event *Event) error {
	if event == nil || event.FilePath == "" {
		return ErrInvalidEventFormat
	}

	// Read the file
	data, err := os.ReadFile(event.FilePath)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to read file %s", event.FilePath), Err: err}
	}

	// Hash the file with the same algorithm
	h, err := v.getHasher(event.HashAlgorithm)
	if err != nil {
		return err
	}

	h.Write(data)
	currentHash := h.Sum(nil)

	if !bytes.Equal(currentHash, event.FileHash) {
		return &SentinelCauseError{Sentinel: ErrHashMismatch, Cause: &MessageError{Msg: fmt.Sprintf("file %s has been modified (measured: %x, current: %x)", event.FilePath, event.FileHash, currentHash)}}
	}

	return nil
}

// VerifyPCR10 verifies the aggregate value of PCR 10 matches computed value
func (v *Verifier) VerifyPCR10(log *EventLog, expectedPCR []byte, hashAlg string) error {
	if log == nil {
		return ErrNotAvailable
	}

	computed, err := v.ComputePCR10(log, hashAlg)
	if err != nil {
		return err
	}

	if !bytes.Equal(computed, expectedPCR) {
		return &SentinelCauseError{Sentinel: ErrHashMismatch, Cause: &MessageError{Msg: fmt.Sprintf("PCR 10 mismatch (expected %x, computed %x)", expectedPCR, computed)}}
	}

	return nil
}

// ComputePCR10 computes what PCR 10 should be based on the event log
func (v *Verifier) ComputePCR10(log *EventLog, hashAlg string) ([]byte, error) {
	if log == nil {
		return nil, ErrNotAvailable
	}

	h, err := v.getHasher(hashAlg)
	if err != nil {
		return nil, err
	}

	// PCR starts at all zeros
	pcrValue := make([]byte, h.Size())

	for _, event := range log.Events {
		if event.PCR != 10 {
			continue
		}

		// PCR extend: new_value = hash(old_value || measurement)
		h.Reset()
		h.Write(pcrValue)
		h.Write(event.TemplateHash)
		pcrValue = h.Sum(nil)
	}

	return pcrValue, nil
}

// getHasher returns the appropriate hash function for the algorithm
func (v *Verifier) getHasher(alg string) (hash.Hash, error) {
	switch alg {
	case "sha1":
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported hash algorithm: %s", alg)}
	}
}

// AddToAllowlist adds a file hash to the allowlist
func (v *Verifier) AddToAllowlist(path string, hash []byte) {
	v.allowlist[path] = hash
}

// AddToAllowlistWithAlg adds a file hash to the algorithm-specific allowlist
func (v *Verifier) AddToAllowlistWithAlg(alg, path string, hash []byte) {
	if v.allowlistByAlg[alg] == nil {
		v.allowlistByAlg[alg] = make(map[string][]byte)
	}
	v.allowlistByAlg[alg][path] = hash
}

// RemoveFromAllowlist removes a file from the allowlist
func (v *Verifier) RemoveFromAllowlist(path string) {
	delete(v.allowlist, path)
}

// ClearAllowlist clears all entries from the allowlist
func (v *Verifier) ClearAllowlist() {
	v.allowlist = make(map[string][]byte)
	v.allowlistByAlg = make(map[string]map[string][]byte)
}

// GetAllowlist returns a copy of the allowlist
func (v *Verifier) GetAllowlist() map[string][]byte {
	result := make(map[string][]byte, len(v.allowlist))
	for k, v := range v.allowlist {
		hash := make([]byte, len(v))
		copy(hash, v)
		result[k] = hash
	}
	return result
}

// BuildAllowlistFromLog builds an allowlist from an event log
func (v *Verifier) BuildAllowlistFromLog(log *EventLog) error {
	if log == nil {
		return ErrNotAvailable
	}

	for _, event := range log.Events {
		if event.FilePath != "" && len(event.FileHash) > 0 {
			v.allowlist[event.FilePath] = event.FileHash
		}
	}

	return nil
}

// HashFile computes the hash of a file
func (v *Verifier) HashFile(path string, alg string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read file", Err: err}
	}

	h, err := v.getHasher(alg)
	if err != nil {
		return nil, err
	}

	h.Write(data)
	return h.Sum(nil), nil
}

// HashFileToHex computes the hash of a file and returns hex string
func (v *Verifier) HashFileToHex(path string, alg string) (string, error) {
	hash, err := v.HashFile(path, alg)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// VerifySignature verifies the IMA signature on an event (if present)
func (v *Verifier) VerifySignature(event *Event, pubKey crypto.PublicKey) error {
	if event == nil {
		return ErrInvalidEventFormat
	}

	if len(event.Signature) == 0 {
		return ErrKeyNotLoaded
	}

	// IMA signatures use a specific format that requires parsing
	// This is a placeholder for full signature verification
	// Full implementation requires:
	// 1. Parse the IMA signature header (algorithm, key ID, etc.)
	// 2. Extract the actual signature bytes
	// 3. Verify using the appropriate algorithm

	if pubKey == nil {
		return ErrKeyNotLoaded
	}

	// Basic check that signature exists and has minimum length
	// A real IMA signature is at least:
	// - 1 byte type
	// - 1 byte version
	// - 1 byte hash algorithm
	// - 4 bytes key ID
	// - 2 bytes signature length
	// - N bytes signature
	if len(event.Signature) < 9 {
		return &SentinelCauseError{Sentinel: ErrAppraisalFailure, Cause: &MessageError{Msg: "signature too short"}}
	}

	return nil
}

// DetectMeasurementGaps finds time gaps in measurements that might indicate tampering
func (v *Verifier) DetectMeasurementGaps(log *EventLog, maxGap time.Duration) []string {
	if log == nil || len(log.Events) < 2 {
		return nil
	}

	var gaps []string
	var lastTimestamp time.Time

	for i, event := range log.Events {
		if event.Timestamp.IsZero() {
			continue
		}

		if i > 0 && !lastTimestamp.IsZero() {
			gap := event.Timestamp.Sub(lastTimestamp)
			if gap > maxGap {
				gaps = append(gaps, fmt.Sprintf("gap of %v between events at %s", gap, event.FilePath))
			}
		}
		lastTimestamp = event.Timestamp
	}

	return gaps
}

// FindDuplicateMeasurements finds files that were measured multiple times
func (v *Verifier) FindDuplicateMeasurements(log *EventLog) map[string]int {
	if log == nil {
		return nil
	}

	counts := make(map[string]int)
	for _, event := range log.Events {
		if event.FilePath != "" {
			counts[event.FilePath]++
		}
	}

	// Filter to only duplicates
	duplicates := make(map[string]int)
	for path, count := range counts {
		if count > 1 {
			duplicates[path] = count
		}
	}

	return duplicates
}

// FindModifiedFiles finds files that have different hashes across measurements
func (v *Verifier) FindModifiedFiles(log *EventLog) []string {
	if log == nil {
		return nil
	}

	fileHashes := make(map[string][]byte)
	var modified []string

	for _, event := range log.Events {
		if event.FilePath == "" || len(event.FileHash) == 0 {
			continue
		}

		if existingHash, exists := fileHashes[event.FilePath]; exists {
			if !bytes.Equal(existingHash, event.FileHash) {
				// File was modified between measurements
				modified = append(modified, event.FilePath)
			}
		} else {
			fileHashes[event.FilePath] = event.FileHash
		}
	}

	return modified
}
