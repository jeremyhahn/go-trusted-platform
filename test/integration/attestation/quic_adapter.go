//go:build integration

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

package attestation

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	quicgo "github.com/quic-go/quic-go"
)

// QUICAdapterError represents an error from the QUIC adapter
type QUICAdapterError struct {
	Operation string
	Message   string
}

func (e *QUICAdapterError) Error() string {
	return fmt.Sprintf("QUIC adapter error [%s]: %s", e.Operation, e.Message)
}

// QUICAdapter implements AttestationCommands using QUIC protocol
type QUICAdapter struct {
	endpoint   string
	conn       *quicgo.Conn
	tlsConfig  *tls.Config
	quicConfig *quicgo.Config
}

// NewQUICAdapter creates a new QUIC adapter
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:  GetQUICEndpoint(),
		tlsConfig: helpers.QUICTLSConfig(),
		quicConfig: &quicgo.Config{
			EnableDatagrams: true,
		},
	}
}

// Setup prepares the adapter for testing
func (a *QUICAdapter) Setup(ctx context.Context) error {
	conn, err := quicgo.DialAddr(ctx, a.endpoint, a.tlsConfig, a.quicConfig)
	if err != nil {
		return &QUICAdapterError{
			Operation: "Setup",
			Message:   "failed to connect: " + err.Error(),
		}
	}

	a.conn = conn
	return nil
}

// Teardown cleans up after testing
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.CloseWithError(0, "teardown")
	}
	return nil
}

// Name returns the adapter name
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// doRequest performs a QUIC request and returns the response
// ErrQUICStatus reports a non-OK status byte from the daemon, carrying the
// byte itself so a test can assert WHICH refusal it got rather than only that
// something failed. A broken adapter errors too -- this adapter wrote a JSON
// {method,path,body} envelope past a server that reads opcode framing, and
// every call failed in a way indistinguishable from a refusal. Only an adapter
// speaking the server's framing can produce this type.
type ErrQUICStatus struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICStatus) Error() string {
	return fmt.Sprintf("QUIC %s refused with status 0x%02X: %s", e.Operation, e.Status, e.Message)
}

func (a *QUICAdapter) doOp(ctx context.Context, op string, opcode byte, body interface{}) ([]byte, error) {

	if a.conn == nil {
		return nil, &QUICAdapterError{Operation: op, Message: "adapter is not connected; call Setup first"}
	}

	stream, err := a.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, &QUICAdapterError{Operation: op, Message: "failed to open stream: " + err.Error()}
	}
	defer stream.Close()

	var payload []byte
	if body != nil {
		payload, err = quicwire.EncodePayload(body)
		if err != nil {
			return nil, &QUICAdapterError{Operation: op, Message: "encode: " + err.Error()}
		}
	}

	// token_len is zero: the daemon authenticates these connections by the
	// mTLS client certificate, not a bearer token.
	if err := quicwire.WriteRequest(stream, &quicwire.Request{Opcode: opcode, Payload: payload}); err != nil {
		return nil, &QUICAdapterError{Operation: op, Message: "write request: " + err.Error()}
	}

	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return nil, &QUICAdapterError{Operation: op, Message: "read response: " + err.Error()}
	}

	if resp.Status != quicwire.StatusOK {
		msg := string(resp.Payload)
		if msg == "" {
			msg = quicwire.StatusToString(resp.Status)
		}
		return nil, ErrQUICStatus{Operation: op, Status: resp.Status, Message: msg}
	}
	return resp.Payload, nil
}

// =============================================================================
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM
func (a *QUICAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GenerateVMQuote"}
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate
func (a *QUICAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GetVMIdentity"}
}

// GetVMAttestation generates a full VM attestation
func (a *QUICAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	body, err := a.doOp(ctx, "GetVMAttestation", quicwire.OpAttestVMWorkload, opts)
	if err != nil {
		return nil, err
	}

	var result GetVMAttestationResult
	if err := quicwire.DecodePayload(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetVMAttestation",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// VerifyVMAttestation verifies a VM attestation
func (a *QUICAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "VerifyVMAttestation"}
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations
func (a *QUICAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	body, err := a.doOp(ctx, "BuildManifest", quicwire.OpAttestBuildManifest, opts)
	if err != nil {
		return nil, err
	}

	var result BuildManifestResult
	if err := quicwire.DecodePayload(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "BuildManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// SignManifest signs a manifest with the host TPM
func (a *QUICAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "SignManifest"}
}

// VerifyManifest fetches the stored manifest and posts it to
// OpAttestVerifyManifest, which takes the manifest itself, as the REST and
// gRPC adapters do (docs/attestation/api.md §3).
func (a *QUICAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	m, err := a.fetchManifest(ctx, "VerifyManifest/GetManifest", opts.ManifestID)
	if err != nil {
		return nil, err
	}

	body, err := a.doOp(ctx, "VerifyManifest", quicwire.OpAttestVerifyManifest, quicapi.VerifyManifestRequest{Manifest: m})
	if err != nil {
		return nil, err
	}

	var resp quicapi.VerifyManifestResponse
	if err := quicwire.DecodePayload(body, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "VerifyManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	hostIDMatch := true
	if opts.ExpectedHostID != "" {
		hostIDMatch = m.HostID == opts.ExpectedHostID
	}
	return &VerifyManifestResult{
		Valid:           resp.Valid,
		ManifestID:      opts.ManifestID,
		SignatureValid:  resp.SignatureValid,
		MerkleRootValid: resp.MerkleRootValid,
		HostIDMatch:     hostIDMatch,
		SignerTrusted:   resp.SignatureValid,
		Errors:          resp.Errors,
	}, nil
}

// GetManifest retrieves a manifest by ID
func (a *QUICAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	m, err := a.fetchManifest(ctx, "GetManifest", opts.ManifestID)
	if err != nil {
		return nil, err
	}

	return &GetManifestResult{
		ManifestID:     m.ID,
		HostID:         m.HostID,
		MerkleRoot:     m.MerkleRoot,
		Signature:      m.Signature,
		VMCount:        len(m.VMs),
		ContainerCount: len(m.Containers),
		Timestamp:      time.Unix(m.Timestamp, 0),
		Version:        m.Version,
		Metadata:       m.Metadata,
	}, nil
}

// fetchManifest reads a stored manifest over OpAttestGetManifest. The daemon
// decodes the request as quicapi.GetManifestRequest, keyed "id", so the
// suite's GetManifestOptions cannot travel as is.
func (a *QUICAdapter) fetchManifest(ctx context.Context, op, manifestID string) (*quicapi.ManifestData, error) {
	body, err := a.doOp(ctx, op, quicwire.OpAttestGetManifest, quicapi.GetManifestRequest{ID: manifestID})
	if err != nil {
		return nil, err
	}

	var resp quicapi.GetManifestResponse
	if err := quicwire.DecodePayload(body, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: op,
			Message:   "failed to parse response: " + err.Error(),
		}
	}
	if resp.Manifest == nil {
		return nil, &QUICAdapterError{Operation: op, Message: ErrMissingResponseField{Field: "manifest"}.Error()}
	}
	return resp.Manifest, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target
func (a *QUICAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "PushAttestation"}
}

// PushAttestationBatch pushes to multiple targets concurrently
func (a *QUICAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "PushAttestationBatch"}
}

// GetPushStatus retrieves the status of a push operation
func (a *QUICAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GetPushStatus"}
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement
func (a *QUICAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "ExtendWorkloadChain"}
}

// GetWorkloadChainHistory retrieves the chain history
func (a *QUICAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GetWorkloadChainHistory"}
}

// VerifyWorkloadChain verifies the chain against expected PCR
func (a *QUICAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "VerifyWorkloadChain"}
}

// GetWorkloadChainStats retrieves chain statistics
func (a *QUICAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	_ = opts
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GetWorkloadChainStats"}
}

// The device-report verbs have no QUIC opcode (#386).

// ListDeviceReports has no QUIC wire surface.
func (a *QUICAdapter) ListDeviceReports(_ context.Context) (*DeviceReportsResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "ListDeviceReports"}
}

// GetDeviceReport has no QUIC wire surface.
func (a *QUICAdapter) GetDeviceReport(_ context.Context, _ DeviceReportOptions) (*DeviceReport, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GetDeviceReport"}
}

// RefreshDeviceReport has no QUIC wire surface.
func (a *QUICAdapter) RefreshDeviceReport(_ context.Context, _ DeviceReportOptions) (*RefreshDeviceReportResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "RefreshDeviceReport"}
}

// DescribeCallerPolicy has no QUIC wire surface.
func (a *QUICAdapter) DescribeCallerPolicy(_ context.Context) (*calleradmission.Description, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "DescribeCallerPolicy"}
}

// Verify QUICAdapter implements AttestationCommands
var _ AttestationCommands = (*QUICAdapter)(nil)
