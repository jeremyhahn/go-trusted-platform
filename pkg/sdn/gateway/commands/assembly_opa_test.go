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

// With the opa tag an OPA-routed proxy assembles against the real engine
// (#1691).

//go:build opa

package commands

import "testing"

func TestBuildProxyHandlerOPARoutesAssembleWithEvaluator(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.Routes[0].Auth.OPAPolicy = "proxy_authz"
	cfg.OPA.Enabled = true
	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); err != nil {
		t.Fatalf("BuildProxyHandler with opa evaluator: %v", err)
	}
}
