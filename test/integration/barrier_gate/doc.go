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
// Test cases:
//
//  1. TestM6_SealedDaemonRefusesRemotePorts — a fresh daemon configured
//     with seal_strategy=software comes up in the
//     uninitialized state; gate /healthz answers; production REST/gRPC/QUIC
//     ports refuse connections.
//
//  2. TestM6_GateAcceptsInitThenTransitions — POST /init drives the
//     ceremony; once the barrier reports unsealed the gate listener tears
//     down and the production transports bind. Verified by:
//     (a) gate port stops accepting new connections, and
//     (b) production REST port begins accepting connections.
//
//  3. TestM6_WarmBoot_UnsealThenTransitions — a warm-boot variant.
//     The originally-specified "already-unsealed daemon skips gate
//     entirely on restart" cannot be exercised: the platform has no
//     automatic unseal, so the restarted daemon comes up sealed.
//     This test therefore proves the same M6 transition contract
//     (gate → production handoff) via the warm-boot /unseal path:
//     initialize cold → stop → restart (gate binds in sealed state) →
//     POST /unseal → assert production transports come up.
//
// Run via: make integration-test-barrier-gate
package barrier_gate
