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

// Package barrier_gate implements the M6 init-only loopback gate integration
// test from docs/08-bootstrap-auth-architecture.md.
//
// The gate is the listener that platformd binds BEFORE its production
// transports come up. It accepts only:
//
//   - GET  /healthz   reports the current barrier state for orchestrators.
//   - POST /init      one-shot ceremony bootstrap (Uninitialized only).
//   - POST /unseal    submit a secret/share toward the unseal threshold.
//
// All other transports (gRPC TCP, REST, QUIC, MCP) MUST NOT be bound until
// the barrier transitions to unsealed.
//
// TestM6_WarmBoot_UnsealThenTransitions is the suite's one test: it
// initializes a real daemon cold, restarts the process, asserts the gate
// rebinds in the sealed state with the production ports refused, then
// POST /unseal releases the gate and production REST binds. It stays here
// because the barrier surviving a real process restart cannot be shown in
// memory.
//
// The gate's own contract (healthz state, POST /unseal, release on
// unseal) is unit-tested in
// pkg/daemon/commands/serve_barrier_gate_unseal_test.go.
//
// Run via: make integration-test-barrier-gate
package barrier_gate
