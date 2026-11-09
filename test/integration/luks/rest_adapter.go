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

package luks

import (
	"context"
	"os"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// The REST transport registers itself with the platform SDK.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// RESTAdapter implements LUKSCommands through the platform SDK over REST, so
// every call travels the SDK's REST route map and wire decoders exactly as a
// production client's does.
type RESTAdapter struct {
	endpoint string
	// bearer, when set, supplies the bearer the transport presents: the
	// adapter reaches the admin-gated webservice routes with the harness
	// admin session's bearer.
	bearer   func(ctx context.Context) (string, error)
	platform platform.Client
	client   *lukssdk.GRPCClient
}

// NewRESTAdapter creates a new REST protocol adapter instance.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv(EnvPlatformRESTEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformREST
	}
	return &RESTAdapter{endpoint: endpoint, bearer: helpers.HarnessAdminSession().Bearer}
}

// Name returns "REST".
func (r *RESTAdapter) Name() string { return "REST" }

// Setup connects the platform SDK client over REST.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	options := platform.NewOptions(
		platform.WithOnlyProtocol(platform.ProtocolREST),
		platform.WithRESTAddr(r.endpoint),
		platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
	)
	if r.bearer != nil {
		token, err := r.bearer(ctx)
		if err != nil {
			return ErrConnectionFailed{Protocol: "REST", Endpoint: r.endpoint, Err: err}
		}
		options.BearerToken = token
	}
	client, err := platform.Connect(ctx, options)
	if err != nil {
		return ErrConnectionFailed{Protocol: "REST", Endpoint: r.endpoint, Err: err}
	}
	r.platform = client
	r.client = lukssdk.NewGRPCClientFromClient(client.LUKS())
	return nil
}

// Teardown closes the SDK client.
func (r *RESTAdapter) Teardown() error {
	if r.platform != nil {
		return r.platform.Close()
	}
	return nil
}

// Status reports the volume status via the SDK client over REST.
func (r *RESTAdapter) Status(ctx context.Context, req *lukssdk.StatusRequest) (*lukssdk.StatusResponse, error) {
	resp, err := r.client.Status(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Status", Err: err}
	}
	return resp, nil
}

// ListSlots lists the keyslots via the SDK client over REST.
func (r *RESTAdapter) ListSlots(ctx context.Context, req *lukssdk.ListSlotsRequest) (*lukssdk.ListSlotsResponse, error) {
	resp, err := r.client.ListSlots(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "ListSlots", Err: err}
	}
	return resp, nil
}

// Info reads the header info via the SDK client over REST.
func (r *RESTAdapter) Info(ctx context.Context, req *lukssdk.InfoRequest) (*lukssdk.InfoResponse, error) {
	resp, err := r.client.Info(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "Info", Err: err}
	}
	return resp, nil
}

// EnrollPassphrase enrolls a passphrase via the SDK client over REST.
func (r *RESTAdapter) EnrollPassphrase(ctx context.Context, req *lukssdk.EnrollPassphraseRequest) (*lukssdk.EnrollPassphraseResponse, error) {
	resp, err := r.client.EnrollPassphrase(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EnrollPassphrase", Err: err}
	}
	return resp, nil
}

// EnrollFIDO2 enrolls a FIDO2 keyslot via the SDK client over REST.
func (r *RESTAdapter) EnrollFIDO2(ctx context.Context, req *lukssdk.EnrollFIDO2Request) (*lukssdk.EnrollFIDO2Response, error) {
	resp, err := r.client.EnrollFIDO2(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EnrollFIDO2", Err: err}
	}
	return resp, nil
}

// EnrollTPM enrolls a TPM keyslot via the SDK client over REST.
func (r *RESTAdapter) EnrollTPM(ctx context.Context, req *lukssdk.EnrollTPMRequest) (*lukssdk.EnrollTPMResponse, error) {
	resp, err := r.client.EnrollTPM(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EnrollTPM", Err: err}
	}
	return resp, nil
}

// EnrollRecovery enrolls a recovery key via the SDK client over REST.
func (r *RESTAdapter) EnrollRecovery(ctx context.Context, req *lukssdk.EnrollRecoveryRequest) (*lukssdk.EnrollRecoveryResponse, error) {
	resp, err := r.client.EnrollRecovery(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "EnrollRecovery", Err: err}
	}
	return resp, nil
}

// RemoveKey removes a keyslot via the SDK client over REST.
func (r *RESTAdapter) RemoveKey(ctx context.Context, req *lukssdk.RemoveKeyRequest) (*lukssdk.RemoveKeyResponse, error) {
	resp, err := r.client.RemoveKey(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "RemoveKey", Err: err}
	}
	return resp, nil
}

// TestUnlock tests a keyslot via the SDK client over REST.
func (r *RESTAdapter) TestUnlock(ctx context.Context, req *lukssdk.TestUnlockRequest) (*lukssdk.TestUnlockResponse, error) {
	resp, err := r.client.TestUnlock(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "TestUnlock", Err: err}
	}
	return resp, nil
}

// ChangePassphrase changes a passphrase via the SDK client over REST.
func (r *RESTAdapter) ChangePassphrase(ctx context.Context, req *lukssdk.ChangePassphraseRequest) (*lukssdk.ChangePassphraseResponse, error) {
	resp, err := r.client.ChangePassphrase(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "REST", Method: "ChangePassphrase", Err: err}
	}
	return resp, nil
}

var _ LUKSCommands = (*RESTAdapter)(nil)
