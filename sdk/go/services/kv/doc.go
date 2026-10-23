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

// Package kv re-exports the request, response, watch and value types of the
// go-quicbaas key-value client, so a platform SDK consumer can call
// quicbaas.Client.KV() without importing go-quicbaas:
//
//	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kv"
//
// replaces
//
//	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kv"
//	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
//
// without any type conversion. The Put, Get and Delete request types here are
// also the element types of the batch client's Put, Get and Delete verbs.
//
// It adds NO behavior: every identifier is a type alias, a constant bound to
// the upstream value, or a watch option that forwards to its upstream
// counterpart, so a value produced anywhere in the stack is the same value
// here.
//
// The client itself is reached through sdk/go/services/quicbaas
// (Client.KV()); this package does not re-export the upstream NewClient
// constructor, which takes a raw go-quicbaas transport.
package kv
