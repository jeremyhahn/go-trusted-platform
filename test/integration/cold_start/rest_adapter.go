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

package cold_start

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// RESTAdapter drives cold-start operations over HTTPS REST against the
// dedicated cold-start daemon. The auth/factor surface is wired by
// upstream tasks (#143-b/c and surrounding); until it lands every auth
// method returns surface.ErrNoSurface. A 404 or 501 from the daemon is a
// failure, never a skip (#487).
type RESTAdapter struct {
	baseURL string
	client  *http.Client
}

// NewRESTAdapter returns an unconfigured REST adapter.
func NewRESTAdapter() *RESTAdapter { return &RESTAdapter{} }

// Name returns "REST".
func (r *RESTAdapter) Name() string { return "REST" }

// Setup constructs the HTTPS client targeting the harness REST port.
func (r *RESTAdapter) Setup(ctx context.Context, h *Harness) error {
	r.baseURL = GetServiceEndpoints(h.Config()).REST
	r.client = helpers.NewAdminHTTPClient(15 * time.Second)
	return nil
}

// Teardown closes idle connections.
func (r *RESTAdapter) Teardown() error {
	if r.client != nil {
		r.client.CloseIdleConnections()
	}
	return nil
}

// Health invokes GET /healthz.
func (r *RESTAdapter) Health(ctx context.Context) (*HealthSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		State string `json:"state"`
		Ready bool   `json:"ready"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return &HealthSnapshot{State: body.State, Ready: body.Ready}, nil
}

// AddMTLSFactor posts to /api/v1/auth/factor.
func (r *RESTAdapter) AddMTLSFactor(ctx context.Context, username, bundlePath, label string) error {
	return notWired("REST", "auth factor add")
}

// ListFactors GETs /api/v1/auth/factor.
func (r *RESTAdapter) ListFactors(ctx context.Context, username string) ([]FactorRecord, error) {
	return nil, notWired("REST", "auth factor list")
}

// LoginMTLS posts to /api/v1/auth/login.
func (r *RESTAdapter) LoginMTLS(ctx context.Context, username, bundlePath string) (*LoginSnapshot, error) {
	return nil, notWired("REST", "auth login")
}

// RotateMTLSFactor PUTs /api/v1/auth/factor/{id}.
func (r *RESTAdapter) RotateMTLSFactor(ctx context.Context, username, factorID, newBundlePath string) (string, error) {
	return "", notWired("REST", "auth factor rotate")
}

// RemoveFactor DELETEs /api/v1/auth/factor/{id}.
func (r *RESTAdapter) RemoveFactor(ctx context.Context, username, factorID string) error {
	return notWired("REST", "auth factor remove")
}

// notWired declares that an adapter method has no transport surface yet.
// Tests fail on the typed declaration, never match its text (#487, #260).
func notWired(protocol, method string) error {
	return surface.ErrNoSurface{Transport: protocol, Operation: method, Reason: "blocked by #143-b/c follow-ups"}
}

var _ ColdStartCommands = (*RESTAdapter)(nil)
