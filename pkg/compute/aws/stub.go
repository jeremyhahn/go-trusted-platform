//go:build !awscompute

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

// Package aws provides the AWS EC2 NitroTPM compute orchestrator. This file
// is the negated-tag stub: it keeps the package buildable (so `go build ./...`
// succeeds without the awscompute tag) and preserves the New constructor's
// signature. The stub never registers a factory, so the provider resolver
// fails closed with a typed ErrComputeProviderNotCompiled when an operator
// selects the AWS provider in a binary built without the awscompute tag.
package aws

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// ErrProviderNotCompiled is the typed error returned by the stub New. It is a
// compute.ErrComputeProviderNotCompiled for ProviderAWS so callers can match
// the same error whether they hit the resolver or call New directly.
var ErrProviderNotCompiled error = &compute.ErrComputeProviderNotCompiled{Provider: compute.ProviderAWS}

// New returns ErrProviderNotCompiled when the awscompute build tag is absent.
// The real implementation lives in orchestrator.go behind //go:build
// awscompute.
func New(_ context.Context, _ *compute.OrchestratorConfig, _ *compute.Deps) (compute.Orchestrator, error) {
	return nil, ErrProviderNotCompiled
}
