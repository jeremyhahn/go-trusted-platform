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

// Package sdlc re-exports the request, response and record types of the
// go-quicbaas SDLC module client, so a platform SDK consumer can call
// quicbaas.Client.SDLC() without importing go-quicbaas:
//
//	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdlc"
//
// replaces
//
//	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/sdlc"
//
// without any type conversion.
//
// It adds NO behavior: every identifier is a type alias, so a value produced
// anywhere in the stack is the same value here.
//
// The client itself is reached through sdk/go/services/quicbaas
// (Client.SDLC()). This package does not re-export the upstream NewClient
// constructor or SDLCCapableTransport: both concern implementing a
// go-quicbaas transport, not calling the module.
package sdlc
