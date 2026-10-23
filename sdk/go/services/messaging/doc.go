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

// Package messaging re-exports the request, response and value types of the
// go-quicbaas messaging (push notification) client, so a platform SDK
// consumer can call quicbaas.Client.Messaging() without importing
// go-quicbaas:
//
//	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/messaging"
//
// replaces
//
//	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/messaging"
//
// without any type conversion.
//
// It adds NO behavior: every identifier is a type alias, a constant bound to
// the upstream value, or a constructor that returns the upstream helper
// unchanged (NewDeltaBuilder, NewDeltaApplier), so a value produced anywhere
// in the stack is the same value here. The delta helpers are re-exported
// because their state is unexported upstream: without the constructors a
// subscriber could not apply the DeltaPayload a delta notification carries.
//
// The client itself is reached through sdk/go/services/quicbaas
// (Client.Messaging()); this package does not re-export the upstream
// NewClient constructor, which takes a raw go-quicbaas transport.
package messaging
