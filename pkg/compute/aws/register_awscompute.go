//go:build awscompute

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

package aws

import "github.com/jeremyhahn/go-trusted-platform/pkg/compute"

// init registers the AWS EC2 NitroTPM orchestrator with the compute provider
// factory. It runs only when this package is linked into the build, which
// happens only under the awscompute build tag (the daemon blank-imports this
// package from a tagged file). Without the tag, ProviderAWS has no registered
// factory and NewOrchestratorForConfig fails closed with a typed
// ErrComputeProviderNotCompiled.
func init() {
	compute.RegisterOrchestrator(compute.ProviderAWS, New)
}
