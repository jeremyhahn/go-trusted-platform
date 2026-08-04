//go:build gcpcompute

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

package commands

// Blank-importing the GCP compute package runs its init(), which registers the
// GCP Shielded VM orchestrator with the compute provider factory. This import
// exists only under the gcpcompute build tag; without it the daemon never
// links the GCP SDK and the provider resolver fails closed for a config that
// selects provider: gcp.
import _ "github.com/jeremyhahn/go-trusted-platform/pkg/compute/gcp"
