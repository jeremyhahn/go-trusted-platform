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

// Package push provides infrastructure for pushing attestation manifests
// to remote verification services, policy engines, and monitoring systems.
//
// The push package enables secure distribution of host attestation data
// to configured endpoints using multiple transport protocols. It supports:
//   - HTTP/HTTPS transport with mTLS authentication
//   - gRPC transport for high-performance service communication
//   - Configurable retry logic with exponential backoff
//   - Multiple push targets with independent configurations
//   - Scheduled periodic pushes and on-change triggers
//   - Context-aware operations with cancellation support
//
// Key components:
//   - PushClient: Handles transport and authentication for remote endpoints
//   - PushScheduler: Manages timing and triggering of push operations
//   - PushConfig: Configuration for targets, retries, and intervals
//
// Push Workflow:
//  1. Configure targets with endpoints and authentication
//  2. Initialize PushClient with transport options
//  3. Start PushScheduler for periodic or triggered pushes
//  4. Manifests are serialized and sent to all enabled targets
//  5. Results are collected with success/failure status
//
// Security Considerations:
//   - mTLS ensures mutual authentication between client and server
//   - TLS 1.3 minimum for transport security
//   - Authentication tokens for additional authorization
//   - Signed manifests provide integrity and non-repudiation
package push
