// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package ipsec protects the overlay underlay with host-to-host IPsec. It
// drives strongSwan's charon over VICI: one transport-mode SA per VTEP pair,
// covering VXLAN and the BGP session between them, trapped on demand from
// the admitted EVPN Type-3 routes and kept explicit (no wildcard) toward the
// route reflectors and gateways. Beside charon it owns the fail-closed
// floor that keeps cleartext off the fabric when charon is down: an
// nftables table on the fabric interface and a low-priority XFRM block
// policy.
//
// The overlay.ipsec section it runs from lives in pkg/sdn/ipsec/config,
// apart from this data plane, so the SDN configuration does not link it.
//
// Configuration and behaviour: docs/sdn/overlay/.
package ipsec
