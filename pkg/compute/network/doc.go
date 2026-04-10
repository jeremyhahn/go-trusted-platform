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

// Package network provides x509-based network port authentication with VLAN
// transitions and attestation integration.
//
// The package implements certificate-based port authentication that integrates
// with mTLS, TPM attestation, and OPA policy evaluation to securely transition
// devices from quarantine VLANs to production network segments.
//
// # Authentication Flow
//
// The authentication process follows these steps:
//
//  1. Device boots in VLAN 1 (quarantine) with restricted network access
//  2. Device initiates mTLS connection with client certificate
//  3. Service extracts policy OIDs from the certificate extensions
//  4. Service requests attestation from the device's TPM
//  5. Policy is evaluated against OPA rules
//  6. On success: OpenFlow rules are installed, device moves to production VLAN
//
// # Authentication States
//
// Devices transition through the following states:
//
//   - Quarantine: Initial state, restricted network access
//   - Enrolling: Certificate enrollment in progress
//   - Authorized: Full network access with production VLAN
//   - Revoked: Access denied due to certificate/attestation failure
//
// # VLAN Transitions
//
// VLAN transitions are atomic operations that coordinate:
//
//   - OpenFlow rule installation/removal
//   - OVSDB port VLAN tag updates
//   - State machine transitions
//   - Audit logging
//
// # Re-attestation
//
// The package supports periodic re-attestation to ensure continuous compliance:
//
//   - Configurable re-attestation intervals
//   - Grace periods for network access during re-attestation
//   - Automatic quarantine on re-attestation failure
//
// # Integration Points
//
//   - pkg/sdn/policy: SDN policy engine for OpenFlow management
//   - pkg/attestation/vm: TPM attestation verification
//   - OPA: External policy evaluation engine
//
// # Example Usage
//
//	config := &network.AuthConfig{
//	    QuarantineVLAN:   1,
//	    BridgeName:       "br0",
//	    ReattestInterval: 24 * time.Hour,
//	}
//
//	service, err := network.NewNetworkAuthService(config,
//	    network.WithLogger(logger),
//	    network.WithPolicyEngine(policyEngine),
//	    network.WithAttestationVerifier(verifier),
//	)
//	if err != nil {
//	    return err
//	}
//
//	result, err := service.Authenticate(ctx, &network.PortAuthRequest{
//	    PortID:      "eth0",
//	    Certificate: clientCert,
//	})
package network
