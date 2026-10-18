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

// Package batch re-exports the request, response and value types of the
// go-quicbaas atomic batch client, so a platform SDK consumer can call
// quicbaas.Client.Batch() without importing go-quicbaas:
//
//	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/batch"
//
// replaces
//
//	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/batch"
//
// without any type conversion. The Put, Get and Delete verbs take the
// key-value request types, which sdk/go/services/kv re-exports.
//
// It adds NO behavior: every identifier is a type alias or a constant bound to
// the upstream value, so a value produced anywhere in the stack is the same
// value here.
//
// The client itself is reached through sdk/go/services/quicbaas
// (Client.Batch()); this package does not re-export the upstream NewClient
// constructor, which takes a raw go-quicbaas transport.
package batch
