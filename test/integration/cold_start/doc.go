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

//go:build integration

// Package cold_start contains the M9 cold-start lifecycle integration test
// per docs/08-bootstrap-auth-architecture.md §6 and the locked canonical
// init contract.
//
// The suite spawns its own short-lived platformd against a clean data
// directory (NOT the shared auto-unsealed daemon launched for other
// integration suites) and walks through the full cold-start lifecycle:
//
//  1. Fresh data dir.
//  2. platformd starts in init-only mode; remote transports refuse.
//  3. platformctl init --barrier-strategy software succeeds.
//  4. Daemon transitions to operational; remote transports accept.
//  5. Create user.
//  6. Add factors (mTLS works; FIDO2/PIV stubs skipped pending #143-b/c).
//  7. List factors.
//  8. Login via each method (mTLS works; FIDO2/PIV skipped).
//  9. Multi-protocol verification of available paths.
//  10. Lifecycle: rotate mTLS, ErrLastFactor enforcement.
//  11. Restart + unseal + cert persistence.
//
// Run via: make integration-test-cold-start
package cold_start
