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

// Package dns provides integration test adapters for DNS services.
// This file implements the DNSCommands interface over the platform SDK's
// REST transport.

//go:build integration

package dns

import (
	"context"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// The REST transport registers itself with the platform SDK.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// ErrRESTConnectionFailed indicates the SDK could not connect over REST.
type ErrRESTConnectionFailed struct {
	URL string
	Err error
}

func (e ErrRESTConnectionFailed) Error() string {
	return "REST API connection failed to " + e.URL + ": " + e.Err.Error()
}

func (e ErrRESTConnectionFailed) Unwrap() error {
	return e.Err
}

// RESTAdapter implements DNSCommands through the platform SDK over REST. The
// REST DNS routes serve the proto wire shape, so the adapter drives the same
// DNSServiceClient calls as the gRPC adapter; only the transport differs, and
// every call travels the SDK's REST route map exactly as a production
// client's does.
type RESTAdapter struct {
	*GRPCAdapter
	baseURL string
	// bearer supplies the bearer the transport presents: the DNS routes
	// are admin-gated webservice routes, reached with the harness admin
	// session's bearer.
	bearer   func(ctx context.Context) (string, error)
	platform platform.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	endpoint := GetServiceEndpoints().PlatformAPI
	// The REST listener is mTLS: keep the endpoint's scheme (a bare
	// host:port gets https://) and present the runner's client certificate.
	return &RESTAdapter{
		GRPCAdapter: NewGRPCAdapter(),
		baseURL:     helpers.RESTBaseURL(endpoint),
		bearer:      helpers.HarnessAdminSession().Bearer,
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup connects the platform SDK client over REST and verifies the DNS
// routes are mounted by listing zones, the cheapest read they serve.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	options := platform.NewOptions(
		platform.WithOnlyProtocol(platform.ProtocolREST),
		platform.WithRESTAddr(r.baseURL),
		platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
	)
	token, err := r.bearer(ctx)
	if err != nil {
		return ErrRESTConnectionFailed{URL: r.baseURL, Err: err}
	}
	options.BearerToken = token
	client, err := platform.Connect(ctx, options)
	if err != nil {
		return ErrRESTConnectionFailed{URL: r.baseURL, Err: err}
	}
	r.platform = client
	r.dns = client.DNS()

	if _, err := r.dns.ListZones(ctx, &pb.ListZonesRequest{}); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			return ErrRESTConnectionFailed{URL: r.baseURL, Err: closeErr}
		}
		return ErrRESTConnectionFailed{URL: r.baseURL, Err: err}
	}
	return nil
}

// Teardown closes the SDK client.
func (r *RESTAdapter) Teardown() error {
	if r.platform != nil {
		return r.platform.Close()
	}
	return nil
}
