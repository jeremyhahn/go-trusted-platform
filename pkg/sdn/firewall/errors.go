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

package firewall

import "errors"

var (
	// ErrInvalidConfig indicates the firewall configuration is nil or invalid.
	ErrInvalidConfig = errors.New("firewall: invalid configuration")

	// ErrInvalidDefaultPolicy indicates the default policy string is not
	// "allow" or "deny".
	ErrInvalidDefaultPolicy = errors.New("firewall: default policy must be \"allow\" or \"deny\"")

	// ErrUnknownZone indicates a reference to a zone that does not exist.
	ErrUnknownZone = errors.New("firewall: unknown zone")

	// ErrInvalidRule indicates a firewall rule failed validation.
	ErrInvalidRule = errors.New("firewall: invalid rule")

	// ErrRuleMissingName indicates a rule has no name.
	ErrRuleMissingName = errors.New("firewall: rule name is required")

	// ErrConnTrackFull indicates the connection tracking table has reached
	// its maximum capacity.
	ErrConnTrackFull = errors.New("firewall: connection tracking table full")

	// ErrNATPortExhaustion indicates no ephemeral ports are available for
	// NAT translation.
	ErrNATPortExhaustion = errors.New("firewall: NAT port exhaustion")

	// ErrZoneMissingName indicates a zone has no name.
	ErrZoneMissingName = errors.New("firewall: zone name is required")

	// ErrDuplicateZone indicates two zones share the same name.
	ErrDuplicateZone = errors.New("firewall: duplicate zone name")

	// ErrNATRuleMissingName indicates a NAT rule has no name.
	ErrNATRuleMissingName = errors.New("firewall: NAT rule name is required")

	// ErrNATRuleInvalidTarget indicates a DNAT rule has an invalid target.
	ErrNATRuleInvalidTarget = errors.New("firewall: DNAT rule requires valid target IP and port")
)
