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

package container

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// =============================================================================
// Tier 3 — Fleet Container Attestation
// =============================================================================
//
// The platform is Tier 3 of the trusted-agent model: it owns the append-only
// measurement event log, its cumulative-hash chain and its replay, plus the
// device registry and quarantine policy layered on top elsewhere in the tree.
//
// Everything below Tier 3 comes from the go-quicbaas SDK and is NOT
// reimplemented here:
//
//   - orchestration.HostTPM              PCR extension and quotes.
//   - orchestration.ContainerConfigDigest deterministic configuration digest.
//   - ExecContainerRuntime.ResolveImageDigest / ValidateImageDigest
//                                        image content-digest resolution.
//   - AttestingContainerRuntime.Attest    fresh nonce-bound quote plus the
//                                        golden-PCR comparison.
//
// The only trusted-computing operation the platform adds on top of the SDK is
// QuoteVerifier: a fleet verifier must confirm a quote was signed by the IAK
// of the device it believes it is talking to, which a standalone agent
// attesting its own TPM has no need to do.

// AttestationVerificationResult contains the result of container attestation
// verification.
type AttestationVerificationResult struct {
	// ContainerID is the container that was verified.
	ContainerID string `json:"container_id"`

	// ContainerName is the container name.
	ContainerName string `json:"container_name"`

	// Verified indicates if attestation passed all checks.
	Verified bool `json:"verified"`

	// ImageDigest is the verified image content digest, in canonical
	// "sha256:<64 hex>" form.
	ImageDigest string `json:"image_digest"`

	// ConfigDigest is the verified configuration digest, in canonical
	// "sha256:<64 hex>" form.
	ConfigDigest string `json:"config_digest"`

	// PCRValue is the workload PCR value read at attestation time.
	PCRValue []byte `json:"pcr_value"`

	// ExpectedPCRValue is the value derived by replaying the measurement
	// event log.
	ExpectedPCRValue []byte `json:"expected_pcr_value"`

	// Evidence is the SDK attestation evidence the verification is based
	// on. It is nil when attestation failed before a quote was produced.
	Evidence *orchestration.ContainerAttestation `json:"evidence,omitempty"`

	// Timestamp is when verification was performed.
	Timestamp time.Time `json:"timestamp"`

	// Error contains the error message if verification failed.
	Error string `json:"error,omitempty"`
}

// AttestationRuntimeUnavailableError indicates attestation was requested but
// no go-quicbaas attesting container runtime is configured, so no quote can
// be taken and no golden-PCR comparison can be made.
//
// It is returned rather than degrading to an unverified result: an
// attestation call that reports success without a quote is worse than one
// that fails.
type AttestationRuntimeUnavailableError struct {
	// ContainerID is the container attestation was requested for.
	ContainerID string
}

// Error implements the error interface.
func (e *AttestationRuntimeUnavailableError) Error() string {
	msg := "container attestation: no attesting container runtime is configured"
	if e.ContainerID != "" {
		msg += " (container " + e.ContainerID + ")"
	}
	return msg
}

// Unwrap returns the sentinel error for errors.Is support.
func (e *AttestationRuntimeUnavailableError) Unwrap() error {
	return ErrAttestationFailed
}

// QuoteVerifierUnavailableError indicates the host TPM cannot verify quote
// signatures, so a fleet verifier cannot bind a quote to a device identity.
type QuoteVerifierUnavailableError struct {
	// ContainerID is the container attestation was requested for.
	ContainerID string
}

// Error implements the error interface.
func (e *QuoteVerifierUnavailableError) Error() string {
	msg := "container attestation: host TPM cannot verify quote signatures"
	if e.ContainerID != "" {
		msg += " (container " + e.ContainerID + ")"
	}
	return msg
}

// Unwrap returns the sentinel error for errors.Is support.
func (e *QuoteVerifierUnavailableError) Unwrap() error {
	return ErrQuoteVerificationFailed
}

// ContainerAttestor owns the platform's container measurement event log and
// drives the go-quicbaas SDK trust tiers over it.
//
// It holds two SDK seams because they answer different questions:
//
//   - tpm (orchestration.HostTPM) extends each measurement-log event into the
//     workload PCR as the event is recorded.
//   - runtime (orchestration.AttestingContainerRuntime) takes a fresh quote
//     and compares it against the golden PCR value the log replay produces.
//
// The runtime is optional at construction so an orchestrator can still record
// measurements on a host with no container runtime binary; verification then
// fails closed with AttestationRuntimeUnavailableError.
type ContainerAttestor struct {
	tpm      orchestration.HostTPM
	runtime  orchestration.AttestingContainerRuntime
	verifier QuoteVerifier
	log      *ThreadSafeMeasurementLog
	pcrIndex int
	bank     string
	closed   atomic.Bool
}

// ContainerAttestorOption configures a ContainerAttestor.
type ContainerAttestorOption func(*ContainerAttestor)

// WithPCRIndex sets the PCR index to use for container measurements.
// Default is the WorkloadPCR index (14).
func WithPCRIndex(index int) ContainerAttestorOption {
	return func(a *ContainerAttestor) {
		a.pcrIndex = index
	}
}

// WithMeasurementBank sets the PCR bank measurements are extended into.
// Default is the SDK's default bank (sha256).
func WithMeasurementBank(bank string) ContainerAttestorOption {
	return func(a *ContainerAttestor) {
		a.bank = bank
	}
}

// WithThreadSafeMeasurementLog sets a pre-existing measurement log.
// This is useful for restoring state from persistence.
func WithThreadSafeMeasurementLog(log *ThreadSafeMeasurementLog) ContainerAttestorOption {
	return func(a *ContainerAttestor) {
		a.log = log
	}
}

// WithAttestingRuntime sets the go-quicbaas attesting container runtime that
// produces quotes and performs the golden-PCR comparison.
func WithAttestingRuntime(runtime orchestration.AttestingContainerRuntime) ContainerAttestorOption {
	return func(a *ContainerAttestor) {
		a.runtime = runtime
	}
}

// WithQuoteVerifier sets the Tier-3 quote signature verifier. When unset, a
// host TPM that implements QuoteVerifier supplies it automatically.
func WithQuoteVerifier(verifier QuoteVerifier) ContainerAttestorOption {
	return func(a *ContainerAttestor) {
		a.verifier = verifier
	}
}

// NewContainerAttestor creates a ContainerAttestor over the go-quicbaas SDK
// host TPM seam.
func NewContainerAttestor(tpm orchestration.HostTPM, opts ...ContainerAttestorOption) (*ContainerAttestor, error) {
	if tpm == nil {
		return nil, ErrHostTPMRequired{}
	}

	a := &ContainerAttestor{
		tpm:      tpm,
		log:      NewThreadSafeMeasurementLog(),
		pcrIndex: DefaultPCRIndex,
		bank:     orchestration.DefaultMeasurementBank,
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.verifier == nil {
		if verifier, ok := tpm.(QuoteVerifier); ok {
			a.verifier = verifier
		}
	}
	if a.bank == "" {
		a.bank = orchestration.DefaultMeasurementBank
	}
	if a.pcrIndex < 0 || a.pcrIndex > orchestration.MaxPCRIndex {
		return nil, ErrInvalidSpec
	}

	return a, nil
}

// ComputeContainerEntryHash computes the combined hash for a container
// measurement. This is the hash that will be extended to the PCR.
func (a *ContainerAttestor) ComputeContainerEntryHash(
	containerID string,
	imageDigest, configDigest string,
) ([]byte, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if containerID == "" {
		return nil, ErrInvalidContainerID
	}

	return ComputeEntryHash(containerID, imageDigest, configDigest, EventContainerCreate), nil
}

// Attest produces fresh attestation evidence for a container and verifies it
// against the replayed measurement log.
//
// The work is split across the layer boundary:
//
//	Tier 3 (here)  replay the append-only event log into the golden value of
//	               the workload PCR, and recover the image identity the
//	               container was created from. The SDK has no event-log model,
//	               so neither can come from it.
//	Tier 1 (SDK)   take a fresh, nonce-bound quote and compare the quoted PCR
//	               set against that golden value. The comparison and its typed
//	               PCRMismatchError belong to the SDK attesting runtime.
func (a *ContainerAttestor) Attest(
	ctx context.Context,
	containerID string,
	log *ThreadSafeMeasurementLog,
) (*orchestration.ContainerAttestation, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}
	if containerID == "" {
		return nil, ErrInvalidContainerID
	}
	if log == nil {
		return nil, ErrMeasurementLogInvalid
	}
	if a.runtime == nil {
		return nil, &AttestationRuntimeUnavailableError{ContainerID: containerID}
	}

	identity, err := log.FindImageIdentity(containerID)
	if err != nil {
		return nil, err
	}

	spec, err := a.attestationSpec(identity, log.ComputeExpectedPCR())
	if err != nil {
		return nil, err
	}

	return a.runtime.Attest(ctx, spec, containerID)
}

// attestationSpec builds the SDK container spec the golden-PCR comparison is
// driven from: the image identity recorded at container creation, plus the
// replayed workload PCR as the single expected value.
func (a *ContainerAttestor) attestationSpec(
	identity *MeasurementEntry,
	expectedPCR []byte,
) (*orchestration.ContainerSpec, error) {
	image := identity.Image
	if image == "" {
		// A log written before the image reference was recorded still
		// carries the digest, which is the identity that matters; the
		// repository part is cosmetic in the pinned reference.
		image = identity.ImageDigest
	}

	spec := &orchestration.ContainerSpec{
		Name:            identity.ContainerName,
		Image:           image,
		ImageDigest:     identity.ImageDigest,
		TrustLevel:      orchestration.TrustLevelAttested,
		MeasurementBank: a.bank,
		ExpectedPCRs: map[uint32][]byte{
			uint32(a.pcrIndex): expectedPCR,
		},
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return spec, nil
}

// VerifyAttestation verifies a container's attestation end to end: the SDK
// takes a fresh quote and compares it against the replayed measurement log,
// and the platform then confirms the quote was signed by the host's IAK.
//
// A verifier that skipped the signature check would accept a quote from any
// TPM; a verifier that skipped the replay would accept any PCR value. Both
// are required, and both must succeed for Verified to be true.
func (a *ContainerAttestor) VerifyAttestation(
	ctx context.Context,
	containerID string,
	log *ThreadSafeMeasurementLog,
) (*AttestationVerificationResult, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}
	if containerID == "" {
		return nil, ErrInvalidContainerID
	}
	if log == nil {
		return nil, ErrMeasurementLogInvalid
	}

	result := &AttestationVerificationResult{
		ContainerID:      containerID,
		Timestamp:        time.Now(),
		ExpectedPCRValue: log.ComputeExpectedPCR(),
	}

	if a.verifier == nil {
		result.Error = "host TPM cannot verify quote signatures"
		return result, &QuoteVerifierUnavailableError{ContainerID: containerID}
	}

	identity, err := log.FindImageIdentity(containerID)
	if err != nil {
		result.Error = "container not found in measurement log"
		return result, err
	}
	result.ContainerName = identity.ContainerName
	result.ImageDigest = identity.ImageDigest
	result.ConfigDigest = identity.ConfigDigest

	evidence, err := a.Attest(ctx, containerID, log)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.Evidence = evidence
	result.PCRValue = evidence.PCRs[uint32(a.pcrIndex)]

	if err := a.verifier.VerifyQuote(ctx, evidence.Quoted, evidence.Signature); err != nil {
		result.Error = "quote verification failed: " + err.Error()
		return result, ErrQuoteVerificationFailed
	}

	result.Verified = true
	return result, nil
}

// RecordContainerCreate records a container creation event and extends the
// workload PCR. It is the only event that carries the image and configuration
// identity; later events reference the container by ID.
func (a *ContainerAttestor) RecordContainerCreate(
	ctx context.Context,
	containerID string,
	containerName string,
	image string,
	imageDigest, configDigest string,
) error {
	if imageDigest == "" || configDigest == "" {
		return &UnmeasuredLaunchError{
			ContainerID:   containerID,
			ContainerName: containerName,
			Stage:         "record_create",
			Cause:         ErrMeasurementLogInvalid,
		}
	}
	return a.recordEvent(ctx, containerID, containerName, image, EventContainerCreate,
		imageDigest, configDigest, "container created")
}

// RecordContainerStart records a container start event and extends the
// workload PCR.
func (a *ContainerAttestor) RecordContainerStart(
	ctx context.Context,
	containerID string,
	containerName string,
) error {
	// Start, stop and remove events carry no digests: the image and
	// configuration were measured at creation and cannot change afterwards.
	return a.recordEvent(ctx, containerID, containerName, "", EventContainerStart, "", "", "container started")
}

// RecordContainerStop records a container stop event and extends the
// workload PCR.
func (a *ContainerAttestor) RecordContainerStop(
	ctx context.Context,
	containerID string,
	containerName string,
) error {
	return a.recordEvent(ctx, containerID, containerName, "", EventContainerStop, "", "", "container stopped")
}

// RecordContainerRemove records a container removal event and extends the
// workload PCR.
func (a *ContainerAttestor) RecordContainerRemove(
	ctx context.Context,
	containerID string,
	containerName string,
) error {
	return a.recordEvent(ctx, containerID, containerName, "", EventContainerRemove, "", "", "container removed")
}

// recordEvent records a container lifecycle event and extends the PCR.
//
// The PCR is extended before the entry is appended: a log entry with no
// corresponding PCR extension would make every later replay disagree with the
// TPM, whereas an extension with no entry only makes the replay fail closed.
func (a *ContainerAttestor) recordEvent(
	ctx context.Context,
	containerID string,
	containerName string,
	image string,
	eventType MeasurementEventType,
	imageDigest, configDigest string,
	description string,
) error {
	if a.closed.Load() {
		return ErrOrchestratorClosed
	}

	if containerID == "" {
		return ErrInvalidContainerID
	}
	if err := ctx.Err(); err != nil {
		return NewContainerError(containerID, containerName, "record_measurement", err)
	}

	entry := NewMeasurementEntry(containerID, containerName, eventType, imageDigest, configDigest, description)
	entry.Image = image
	if err := entry.Validate(); err != nil {
		return NewContainerError(containerID, containerName, "record_measurement", err)
	}

	if err := a.tpm.ExtendPCR(a.pcrIndex, a.bank, entry.CumulativeHash); err != nil {
		return NewContainerError(containerID, containerName, "extend_pcr", err)
	}

	return a.log.AppendEntry(entry)
}

// GetMeasurementLog returns the current measurement log.
func (a *ContainerAttestor) GetMeasurementLog() *ThreadSafeMeasurementLog {
	return a.log
}

// GetPCRIndex returns the PCR index used for container measurements.
func (a *ContainerAttestor) GetPCRIndex() int {
	return a.pcrIndex
}

// MeasurementBank returns the PCR bank measurements are extended into.
func (a *ContainerAttestor) MeasurementBank() string {
	return a.bank
}

// Close closes the attestor and releases resources.
func (a *ContainerAttestor) Close() error {
	a.closed.Store(true)
	return nil
}

// UnmeasuredLaunchError indicates a container could not be measured, so it
// was not launched.
//
// The platform fails closed here on purpose. A container that runs while its
// measurement was skipped is indistinguishable, to every downstream verifier,
// from a container that was never approved: the measurement log has no entry
// for it, the workload PCR was never extended, and the attestation report
// still says the launch succeeded.
type UnmeasuredLaunchError struct {
	// ContainerID is the container that could not be measured. It is empty
	// when the failure happened before the container was created.
	ContainerID string

	// ContainerName is the container name from the specification.
	ContainerName string

	// Stage names the measurement step that failed: resolve_image_digest,
	// config_digest or record_create.
	Stage string

	// Cause is the underlying failure.
	Cause error
}

// Error implements the error interface.
func (e *UnmeasuredLaunchError) Error() string {
	msg := "container " + strconv.Quote(e.ContainerName) +
		" was not launched: measurement failed at " + e.Stage
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the sentinel and the cause for errors.Is support.
func (e *UnmeasuredLaunchError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrAttestationFailed}
	}
	return []error{ErrAttestationFailed, e.Cause}
}
