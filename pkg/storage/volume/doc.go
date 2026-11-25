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

// Package volume holds the platform's volume configuration: storage
// classes and the provider that serves each one.
//
// A storage class names what a workload asks for (replicated, general or
// object storage). Which provider serves a class is deployment
// configuration: the Config maps each class to a provider name and the
// construction settings that provider takes, as a map[string]string.
//
// Block providers are reached through a Factory the go-quicbaas SDK will
// supply (SPEC volume row); the platform does not import go-blockstore.
// This package imports no storage backend and constructs no provider
// itself: until a Factory is supplied, every resolve answers
// ErrNoProviderFactory. The object class is not a block class; it routes
// to the object store in pkg/store/object.
package volume
