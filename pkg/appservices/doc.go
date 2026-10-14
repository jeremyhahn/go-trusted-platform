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

// Package appservices is the service layer between platformd's transports
// and the application services of the composed go-quicbaas SDK: Cache,
// Scheduler and Messaging (docs/sdk/architecture.md).
//
// No transport calls the SDK client directly. Each service resolves its SDK
// group on every call, so a daemon whose SDK starts after the transports, or
// does not serve a group at all, answers ErrNotConfigured rather than
// panicking, and starts serving once the group appears. The services
// validate their input before it reaches the SDK and wrap every SDK failure
// in ErrCallFailed, which keeps the cause reachable through errors.Is/As.
package appservices
