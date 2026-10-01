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

package gateway

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// NAT64 Operations

// GetNAT64Status returns the stateful NAT64 translator's health: whether
// the kernel instance is present, the RFC 6052 translation prefix in use,
// the live session count, pool4 usage and the module version. Every field
// except the identity pair is what the kernel reported, so a started
// service whose instance has gone reports InstancePresent false.
func (c *Client) GetNAT64Status(ctx context.Context) (*platformv1.NAT64Status, error) {
	resp, err := c.grpc.GetNAT64Status(ctx, &platformv1.GetNAT64StatusRequest{})
	if err != nil {
		return nil, &ErrGetNAT64StatusFailed{Cause: err}
	}
	return resp.Status, nil
}

// NAT64 Error Types

// ErrGetNAT64StatusFailed is returned when the translator status could not
// be read.
type ErrGetNAT64StatusFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrGetNAT64StatusFailed) Error() string {
	return fmt.Sprintf("failed to get NAT64 status: %v", e.Cause)
}

// Unwrap implements errors.Unwrap.
func (e *ErrGetNAT64StatusFailed) Unwrap() error { return e.Cause }
