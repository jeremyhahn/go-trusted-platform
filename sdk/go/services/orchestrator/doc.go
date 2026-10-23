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

// Package orchestrator re-exports the request, response, record and error
// types of the go-quicbaas orchestrator client, so a platform SDK consumer
// can call quicbaas.Client.Orchestrator() without importing go-quicbaas:
//
//	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestrator"
//
// replaces
//
//	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/orchestrator"
//
// without any type conversion.
//
// It adds NO behavior: every identifier is a type alias or a constant bound to
// the upstream value, so a value produced anywhere in the stack is the same
// value here and errors.As matches EmptyTurnError and MissingTurnIDError
// across the boundary.
//
// The client itself is reached through sdk/go/services/quicbaas
// (Client.Orchestrator()). This package does not re-export what concerns
// implementing a go-quicbaas transport rather than calling the orchestrator:
// the NewClient constructor, the *Wire envelopes and the
// NewPromptSessionAccepted / NewPromptSessionResponse response builders.
//
// The container-trust types a session request names (TrustLevel and the rest)
// live in the sibling package sdk/go/services/orchestration.
package orchestrator
