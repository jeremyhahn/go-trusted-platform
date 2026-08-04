//go:build azurecompute

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

// Blank-importing the Azure compute package runs its init(), which registers
// the Azure Trusted Launch orchestrator with the compute provider factory. This
// import exists only under the azurecompute build tag; without it the daemon
// never links the Azure SDK and the provider resolver fails closed for a config
// that selects provider: azure.
import _ "github.com/jeremyhahn/go-trusted-platform/pkg/compute/azure"
