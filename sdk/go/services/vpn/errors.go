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

package vpn

// Op names a VPNService operation in an ErrCallFailed.
type Op string

// The operations a Client performs.
const (
	OpEnrolPeer           Op = "enrol peer"
	OpListPeers           Op = "list peers"
	OpRevokePeer          Op = "revoke peer"
	OpStatus              Op = "get status"
	OpGetPosturePolicy    Op = "get posture policy"
	OpSetPosturePolicy    Op = "set posture policy"
	OpDeletePosturePolicy Op = "delete posture policy"
	OpListPosturePolicies Op = "list posture policies"
)

// ErrCallFailed is returned when a VPNService call fails. The cause is the
// transport error, which carries the service's status code.
type ErrCallFailed struct {
	Op    Op
	Cause error
}

// Error implements the error interface.
func (e *ErrCallFailed) Error() string {
	return "vpn: " + string(e.Op) + " failed: " + e.Cause.Error()
}

// Unwrap returns the underlying transport error.
func (e *ErrCallFailed) Unwrap() error { return e.Cause }
