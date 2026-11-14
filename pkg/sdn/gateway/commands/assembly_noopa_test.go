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

// A build without the opa tag refuses to assemble a proxy with OPA enabled,
// with the engine's ErrOPANotBuilt (#1691). make test-noopa runs this.

//go:build !opa

package commands

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
)

func TestBuildProxyHandlerOPAEnabled_NoOPA_RefusesNotBuilt(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.Routes[0].Auth.OPAPolicy = "proxy_authz"
	cfg.OPA.Enabled = true
	_, err := BuildProxyHandler(cfg, nil, nil, testLogger())
	var notBuilt opa.ErrOPANotBuilt
	if !errors.As(err, &notBuilt) {
		t.Fatalf("BuildProxyHandler with opa enabled, !opa build = %v, want ErrOPANotBuilt", err)
	}
}
