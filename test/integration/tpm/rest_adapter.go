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

//go:build integration

package tpm

import (
	"context"
	"os"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// The REST transport registers itself with the platform SDK.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// =============================================================================
// REST Protocol Adapter
// =============================================================================

// RESTAdapter implements TPMCommands through the platform SDK over REST, so
// every call travels the SDK's REST route map and protobuf JSON wire exactly
// as a production client's does.
type RESTAdapter struct {
	endpoint string
	platform platform.Client
	client   *tpmsvc.Client
}

// NewRESTAdapter creates a new REST protocol adapter instance.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv(EnvPlatformRESTEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformREST
	}
	return &RESTAdapter{endpoint: endpoint}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup connects the platform SDK client over REST.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, platform.NewOptions(
		platform.WithOnlyProtocol(platform.ProtocolREST),
		platform.WithRESTAddr(r.endpoint),
		platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
	))
	if err != nil {
		return ErrConnectionFailed{Protocol: "REST", Endpoint: r.endpoint, Err: err}
	}
	r.platform = client
	r.client = tpmsvc.NewClientFromGRPC(client.TPM())
	return nil
}

// Teardown closes the SDK client.
func (r *RESTAdapter) Teardown() error {
	if r.platform != nil {
		return r.platform.Close()
	}
	return nil
}

// Info retrieves TPM information via the SDK client over REST.
func (r *RESTAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := r.client.InfoDomain(ctx)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Info", Err: err}
	}
	return infoResultFromResponse(resp), nil
}

// Provision provisions the TPM via the SDK client over REST.
func (r *RESTAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	resp, err := r.client.ProvisionDomain(ctx, provisionRequestFromOptions(opts))
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Provision", Err: err}
	}
	return provisionResultFromResponse(resp), nil
}

// Clear clears the TPM via the SDK client over REST.
func (r *RESTAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	resp, err := r.client.ClearDomain(ctx, opts.OwnerPassword, opts.Confirm)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Clear", Err: err}
	}
	return clearResultFromResponse(resp), nil
}

// EKCreate creates an EK via the SDK client over REST.
func (r *RESTAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	resp, err := r.client.CreateEKDomain(ctx, keyAlgorithmFromString(opts.Algorithm), opts.Persistent)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "CreateEK", Err: err}
	}
	return ekCreateResultFromResponse(resp, opts.Algorithm), nil
}

// EKInfo retrieves EK information via the SDK client over REST.
func (r *RESTAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	resp, err := r.client.GetEKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, handle)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetEK", Err: err}
	}
	return ekInfoResultFromResponse(resp), nil
}

// EKCertificate retrieves the EK certificate via the SDK client over REST.
func (r *RESTAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	resp, err := r.client.GetEKCertificateDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, 0)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetEKCertificate", Err: err}
	}
	return ekCertificateResultFromResponse(resp), nil
}

// EKDelete deletes the EK via the SDK client over REST.
func (r *RESTAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	resp, err := r.client.DeleteEKDomain(ctx, handle, tpmsvc.KeyAlgorithmUnspecified, password)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "DeleteEK", Err: err}
	}
	success, message := statusFields(deleteKeyStatus(resp))
	return &EKDeleteResult{Success: success, Message: message}, nil
}

// SRKCreate creates an SRK via the SDK client over REST.
func (r *RESTAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	resp, err := r.client.CreateSRKDomain(ctx, keyAlgorithmFromString(opts.Algorithm),
		opts.Persistent, opts.Handle, opts.Password)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "CreateSRK", Err: err}
	}
	return srkCreateResultFromResponse(resp, opts.Algorithm), nil
}

// SRKInfo retrieves SRK information via the SDK client over REST.
func (r *RESTAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	resp, err := r.client.GetSRKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, handle)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetSRK", Err: err}
	}
	return srkInfoResultFromResponse(resp), nil
}

// SRKDelete deletes the SRK via the SDK client over REST.
func (r *RESTAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	resp, err := r.client.DeleteSRKDomain(ctx, handle, tpmsvc.KeyAlgorithmUnspecified, password)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "DeleteSRK", Err: err}
	}
	success, message := statusFields(deleteKeyStatus(resp))
	return &SRKDeleteResult{Success: success, Message: message}, nil
}

// Seal seals data to the TPM via the SDK client over REST.
func (r *RESTAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	resp, err := r.client.SealDomain(ctx, sealRequestFromOptions(opts))
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Seal", Err: err}
	}
	return sealResultFromResponse(resp), nil
}

// Unseal unseals data from the TPM via the SDK client over REST.
func (r *RESTAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	resp, err := r.client.UnsealDomain(ctx, unsealRequestFromOptions(opts))
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Unseal", Err: err}
	}
	return unsealResultFromResponse(resp), nil
}

// EventLog reads the TPM event log via the SDK client over REST.
func (r *RESTAdapter) EventLog(ctx context.Context) (*EventLogResult, error) {
	resp, err := r.client.GetEventLogDomain(ctx, "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "GetEventLog", Err: err}
	}
	return eventLogResultFromResponse(resp), nil
}

// Ensure RESTAdapter implements TPMCommands interface.
var _ TPMCommands = (*RESTAdapter)(nil)
