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

package sdn

import "fmt"

// ErrInvalidTCPolicy indicates ovs.tc-policy has an unsupported value.
type ErrInvalidTCPolicy struct {
	// Policy is the rejected tc-policy value.
	Policy string
}

// Error implements the error interface.
func (e ErrInvalidTCPolicy) Error() string {
	return fmt.Sprintf("sdn: invalid ovs tc-policy %q (must be \"none\", \"skip_sw\", or \"skip_hw\")", e.Policy)
}

// ErrTCPolicyWithoutHWOffload indicates ovs.tc-policy is set while
// ovs.hw-offload is disabled.
type ErrTCPolicyWithoutHWOffload struct{}

// Error implements the error interface.
func (ErrTCPolicyWithoutHWOffload) Error() string {
	return "sdn: ovs tc-policy requires hw-offload to be enabled"
}

// ErrDPDKRequiresNetdev indicates ovs.dpdk is configured while the
// datapath is not "netdev".
type ErrDPDKRequiresNetdev struct {
	// Datapath is the configured (non-netdev) datapath value.
	Datapath string
}

// Error implements the error interface.
func (e ErrDPDKRequiresNetdev) Error() string {
	return fmt.Sprintf("sdn: ovs dpdk configuration requires datapath \"netdev\" (got %q)", e.Datapath)
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}
