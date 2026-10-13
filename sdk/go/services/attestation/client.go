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

// Package attestation provides a client for attestation service operations.
package attestation

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/quotebind"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to attestation service operations.
type Client struct {
	grpc platformv1.AttestationServiceClient
}

// NewClient creates a new attestation service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewAttestationServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new attestation service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.AttestationServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// GetManifest retrieves an existing attestation manifest by ID.
func (c *Client) GetManifest(ctx context.Context, id string) (*platformv1.HostManifest, error) {
	resp, err := c.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{Id: id})
	if err != nil {
		return nil, &ErrGetManifestFailed{ID: id, Cause: err}
	}
	return resp.Manifest, nil
}

// BuildManifest builds a new attestation manifest for the host and its workloads.
func (c *Client) BuildManifest(ctx context.Context, req *platformv1.BuildManifestRequest) (*platformv1.HostManifest, error) {
	resp, err := c.grpc.BuildManifest(ctx, req)
	if err != nil {
		return nil, &ErrBuildManifestFailed{Cause: err}
	}
	return resp.Manifest, nil
}

// VerifyManifest verifies an attestation manifest including signature and Merkle root.
func (c *Client) VerifyManifest(ctx context.Context, req *platformv1.VerifyManifestRequest) (*platformv1.ManifestVerificationResult, error) {
	resp, err := c.grpc.VerifyManifest(ctx, req)
	if err != nil {
		return nil, &ErrVerifyManifestFailed{Cause: err}
	}
	return resp.Result, nil
}

// ListManifests lists attestation manifests with optional filtering.
func (c *Client) ListManifests(ctx context.Context, req *platformv1.ListManifestsRequest) ([]*platformv1.HostManifest, uint32, error) {
	resp, err := c.grpc.ListManifests(ctx, req)
	if err != nil {
		return nil, 0, &ErrListManifestsFailed{Cause: err}
	}
	return resp.Manifests, resp.Total, nil
}

// DeleteManifest removes an attestation manifest.
func (c *Client) DeleteManifest(ctx context.Context, id string) error {
	_, err := c.grpc.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{Id: id})
	if err != nil {
		return &ErrDeleteManifestFailed{ID: id, Cause: err}
	}
	return nil
}

// GetAttestationQuote asks the node for a quote over nonce bound to the
// connection the call travels on (#482). The node quotes
// SHA-256(nonce || channel_binding), channel_binding being the TLS exporter
// of that connection (label EXPORTER-attested-peer), and echoes the
// binding. The response is returned only if the echo and the signed quote
// both match the binding this end derives, so a quote relayed from another
// connection is refused with *quotebind.ErrQuoteNotBound. Pass the
// response's channel_binding with the nonce to VerifyAttestationQuote.
// Transports with no TLS 1.3 connection (Unix socket, MCP, embedded)
// refuse the call.
func (c *Client) GetAttestationQuote(ctx context.Context, config *platformv1.AttestationQuoteConfig, nonce []byte) (*platformv1.GetAttestationQuoteResponse, error) {
	var capture quotebind.Capture
	resp, err := c.grpc.GetAttestationQuote(ctx, &platformv1.GetAttestationQuoteRequest{
		Config: config,
		Nonce:  nonce,
	}, capture.Option())
	if err != nil {
		return nil, &ErrGetQuoteFailed{Cause: err}
	}
	if err := capture.CheckEcho(nonce, resp.GetChannelBinding(), resp.GetQuote().GetQuoteData()); err != nil {
		return nil, &ErrGetQuoteFailed{Cause: err}
	}
	return resp, nil
}

// VerifyAttestationQuote verifies a TPM quote against expected values.
// For a quote GetAttestationQuote returned, set channel_binding to the
// binding it echoed: the daemon then expects SHA-256(nonce || binding).
func (c *Client) VerifyAttestationQuote(ctx context.Context, req *platformv1.VerifyAttestationQuoteRequest) (*platformv1.VerifyAttestationQuoteResponse, error) {
	resp, err := c.grpc.VerifyAttestationQuote(ctx, req)
	if err != nil {
		return nil, &ErrVerifyQuoteFailed{Cause: err}
	}
	return resp, nil
}

// CollectHostAttestation collects attestation data from the host TPM,
// bound to the connection the call travels on exactly as
// GetAttestationQuote is: the attestation is returned only if its signed
// quote carries SHA-256(nonce || binding) for this end's binding.
func (c *Client) CollectHostAttestation(ctx context.Context, config *platformv1.AttestationQuoteConfig, nonce []byte) (*platformv1.HostAttestation, error) {
	var capture quotebind.Capture
	resp, err := c.grpc.CollectHostAttestation(ctx, &platformv1.CollectHostAttestationRequest{
		Config: config,
		Nonce:  nonce,
	}, capture.Option())
	if err != nil {
		return nil, &ErrCollectHostAttestationFailed{Cause: err}
	}
	if err := capture.Check(nonce, resp.GetAttestation().GetQuoteData()); err != nil {
		return nil, &ErrCollectHostAttestationFailed{Cause: err}
	}
	return resp.Attestation, nil
}

// CollectVMAttestation collects attestation data from a VM's vTPM.
func (c *Client) CollectVMAttestation(ctx context.Context, vmID string, config *platformv1.AttestationQuoteConfig, nonce []byte) (*platformv1.VMAttestation, error) {
	resp, err := c.grpc.CollectVMAttestation(ctx, &platformv1.CollectVMAttestationRequest{
		VmId:   vmID,
		Config: config,
		Nonce:  nonce,
	})
	if err != nil {
		return nil, &ErrCollectVMAttestationFailed{VMID: vmID, Cause: err}
	}
	return resp.Attestation, nil
}

// CollectContainerAttestation collects attestation data for a container.
func (c *Client) CollectContainerAttestation(ctx context.Context, containerID string) (*platformv1.ContainerAttestation, error) {
	resp, err := c.grpc.CollectContainerAttestation(ctx, &platformv1.CollectContainerAttestationRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return nil, &ErrCollectContainerAttestationFailed{ContainerID: containerID, Cause: err}
	}
	return resp.Attestation, nil
}

// ListDeviceReports returns every device attestation report the control
// plane's reporting cache holds, ordered by device id. Each report carries
// its verdict together with fresh and age_seconds; a consumer that shows the
// verdict without its age misrepresents the report.
func (c *Client) ListDeviceReports(ctx context.Context) ([]*platformv1.DeviceAttestationReport, error) {
	resp, err := c.grpc.ListDeviceReports(ctx, &platformv1.ListDeviceReportsRequest{})
	if err != nil {
		return nil, &ErrListDeviceReportsFailed{Cause: err}
	}
	return resp.GetReports(), nil
}

// GetDeviceReport returns one device's cached attestation report. A device
// the collector has never reached is *ErrNoDeviceReport, which is a
// distinct state and never a failed verdict; a failed verdict is a report
// whose Verified is false.
func (c *Client) GetDeviceReport(ctx context.Context, deviceID string) (*platformv1.DeviceAttestationReport, error) {
	if deviceID == "" {
		return nil, &ErrDeviceIDRequired{}
	}
	resp, err := c.grpc.GetDeviceReport(ctx, &platformv1.GetDeviceReportRequest{DeviceId: deviceID})
	if err != nil {
		if isNeverCollected(err) {
			return nil, &ErrNoDeviceReport{DeviceID: deviceID, Cause: err}
		}
		return nil, &ErrGetDeviceReportFailed{DeviceID: deviceID, Cause: err}
	}
	return resp.GetReport(), nil
}

// RefreshDeviceReport asks the collector to attest a device out of cycle.
// The call returns as soon as the request is enqueued and never carries a
// quote or a verdict; read the report again for the outcome and its age.
func (c *Client) RefreshDeviceReport(ctx context.Context, deviceID string) (*platformv1.RefreshDeviceReportResponse, error) {
	if deviceID == "" {
		return nil, &ErrDeviceIDRequired{}
	}
	resp, err := c.grpc.RefreshDeviceReport(ctx, &platformv1.RefreshDeviceReportRequest{DeviceId: deviceID})
	if err != nil {
		return nil, &ErrRefreshDeviceReportFailed{DeviceID: deviceID, Cause: err}
	}
	return resp, nil
}

// DescribeCallerPolicy returns the node's compiled caller-admission policy:
// which control planes it lets collect its quotes.
func (c *Client) DescribeCallerPolicy(ctx context.Context) (*platformv1.CallerPolicyDescription, error) {
	resp, err := c.grpc.DescribeCallerPolicy(ctx, &platformv1.DescribeCallerPolicyRequest{})
	if err != nil {
		return nil, &ErrDescribeCallerPolicyFailed{Cause: err}
	}
	return resp.GetPolicy(), nil
}

// DeviceVerdictStream receives the device verdicts platformd records, in the
// order it records them. Recv returns an error once the stream ends.
type DeviceVerdictStream interface {
	Recv() (*platformv1.DeviceVerdictEvent, error)
}

// StreamDeviceVerdicts follows every device verdict platformd records from
// now on, until ctx ends. It is how an overlay gateway learns that a device
// failed attestation, or passed again. The caller needs attestation:read,
// and a caller acting for a tenant receives only its own devices' verdicts.
func (c *Client) StreamDeviceVerdicts(ctx context.Context) (DeviceVerdictStream, error) {
	stream, err := c.grpc.StreamDeviceVerdicts(ctx, &platformv1.StreamDeviceVerdictsRequest{})
	if err != nil {
		return nil, &ErrStreamDeviceVerdictsFailed{Cause: err}
	}
	return stream, nil
}

// isNeverCollected recognises the never-collected state, which every
// transport answers as NotFound (MCP since #505 decodes its NotFound code to
// the same status).
func isNeverCollected(err error) bool {
	return status.Code(err) == codes.NotFound
}
