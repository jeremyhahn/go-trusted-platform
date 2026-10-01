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
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// nat64StatusJSON is the translator status as the REST route and the MCP
// tool carry it: the bare status object, not the gRPC reply that wraps it.
// The two transports answer with the same JSON, so one decoder serves
// both.
type nat64StatusJSON struct {
	Active          bool      `json:"active"`
	InstancePresent bool      `json:"instance_present"`
	Prefix          string    `json:"prefix"`
	Instance        string    `json:"instance"`
	Sessions        uint64    `json:"sessions"`
	Pool4Used       uint64    `json:"pool4_used"`
	ModuleVersion   string    `json:"module_version"`
	FlowCount       uint32    `json:"flow_count"`
	LastReconcile   time.Time `json:"last_reconcile"`
	LastError       string    `json:"last_error"`
}

// DecodeNAT64StatusJSON decodes the translator status the REST route and
// the MCP tool return into the gRPC reply. Without it the generic decode
// matched no field of the reply, whose only field is status, and every
// value was dropped (#661 review). A zero last_reconcile means the service
// never converged, so it is left unset rather than encoded as year 1.
func DecodeNAT64StatusJSON(data []byte) (*platformv1.GetNAT64StatusResponse, error) {
	var wire nat64StatusJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &ErrNAT64StatusDecodeFailed{Cause: err}
	}
	status := &platformv1.NAT64Status{
		Active:          wire.Active,
		InstancePresent: wire.InstancePresent,
		Prefix:          wire.Prefix,
		Instance:        wire.Instance,
		Sessions:        wire.Sessions,
		Pool4Used:       wire.Pool4Used,
		ModuleVersion:   wire.ModuleVersion,
		FlowCount:       wire.FlowCount,
		LastError:       wire.LastError,
	}
	if !wire.LastReconcile.IsZero() {
		status.LastReconcile = timestamppb.New(wire.LastReconcile)
	}
	return &platformv1.GetNAT64StatusResponse{Status: status}, nil
}

// ErrNAT64StatusDecodeFailed is returned when a transport's NAT64 status
// payload is not the status object.
type ErrNAT64StatusDecodeFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrNAT64StatusDecodeFailed) Error() string {
	return fmt.Sprintf("gateway: decode NAT64 status: %v", e.Cause)
}

// Unwrap implements errors.Unwrap.
func (e *ErrNAT64StatusDecodeFailed) Unwrap() error { return e.Cause }
