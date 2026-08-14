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

package loadbalancer

import "errors"

// Sentinel errors returned by the load balancer service.
var (
	// ErrNilController is returned when Deps lacks a flow controller.
	ErrNilController = errors.New("loadbalancer: flow controller is nil")

	// ErrNilOVSClient is returned when Deps lacks an OVS client.
	ErrNilOVSClient = errors.New("loadbalancer: ovs client is nil")

	// ErrNilGroupClient is returned when Deps lacks a group client.
	ErrNilGroupClient = errors.New("loadbalancer: group client is nil")

	// ErrNilAllocator is returned when Deps lacks a conntrack zone allocator.
	ErrNilAllocator = errors.New("loadbalancer: conntrack zone allocator is nil")

	// ErrEmptyBridge is returned when no bridge name is configured.
	ErrEmptyBridge = errors.New("loadbalancer: bridge name must be non-empty")

	// ErrInvalidHealthCheck is returned when the health-check interval or
	// timeout is invalid (interval must be positive and greater than the
	// timeout; rise and fall must not be negative).
	ErrInvalidHealthCheck = errors.New("loadbalancer: health check interval must exceed a positive timeout and rise/fall must not be negative")

	// ErrInvalidMaxBackends is returned when MaxBackends is negative.
	ErrInvalidMaxBackends = errors.New("loadbalancer: max backends must not be negative")

	// ErrAlreadyStarted is returned when Start is called on a running service.
	ErrAlreadyStarted = errors.New("loadbalancer: service already started")

	// ErrNotStarted is returned when an operation requires a running service.
	ErrNotStarted = errors.New("loadbalancer: service not started")

	// ErrAlgorithmUnsupported is returned for algorithms the OVS group
	// datapath cannot implement. "least-conn" requires per-connection
	// bookkeeping the switch does not perform; only hash-based selection
	// ("hash", "round-robin") is supported.
	ErrAlgorithmUnsupported = errors.New("loadbalancer: algorithm not supported by the OVS select-group datapath (supported: hash, round-robin)")

	// ErrInvalidVIPAddress is returned when a VIP address is missing or not
	// a valid IPv4 address.
	ErrInvalidVIPAddress = errors.New("loadbalancer: VIP address must be a valid IPv4 address")

	// ErrInvalidVIPPort is returned when a VIP port is zero.
	ErrInvalidVIPPort = errors.New("loadbalancer: VIP port must be non-zero")

	// ErrInvalidProtocol is returned when a VIP protocol is neither "tcp"
	// nor "udp".
	ErrInvalidProtocol = errors.New("loadbalancer: VIP protocol must be \"tcp\" or \"udp\"")

	// ErrNoBackends is returned when a VIP has no backends.
	ErrNoBackends = errors.New("loadbalancer: VIP must have at least one backend")

	// ErrTooManyBackends is returned when a VIP exceeds the configured
	// MaxBackends limit.
	ErrTooManyBackends = errors.New("loadbalancer: VIP backend count exceeds max backends")

	// ErrInvalidBackend is returned when a backend address is missing, not
	// IPv4, or the backend port is zero.
	ErrInvalidBackend = errors.New("loadbalancer: backend must have a valid IPv4 address and non-zero port")

	// ErrDuplicateBackend is returned when a VIP lists the same
	// address:port backend twice.
	ErrDuplicateBackend = errors.New("loadbalancer: duplicate backend for VIP")

	// ErrVIPExists is returned when adding a VIP that is already configured.
	ErrVIPExists = errors.New("loadbalancer: VIP already exists")

	// ErrVIPNotFound is returned when a requested VIP is not configured.
	ErrVIPNotFound = errors.New("loadbalancer: VIP not found")

	// ErrBackendNotFound is returned when a health transition references a
	// backend the VIP does not carry.
	ErrBackendNotFound = errors.New("loadbalancer: backend not found for VIP")

	// ErrGroupIDExhausted is returned when no free group ID remains in the
	// load balancer group range.
	ErrGroupIDExhausted = errors.New("loadbalancer: group ID range exhausted")
)

// OpError wraps a transport or controller failure with the load balancer
// operation that produced it, preserving errors.Is/errors.As matching.
type OpError struct {
	// Op is the operation that failed ("install", "delete", "allocate",
	// "release", "group-add", "group-modify", "group-delete",
	// "group-desc", "reconcile").
	Op string

	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *OpError) Error() string {
	return "loadbalancer: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *OpError) Unwrap() error {
	return e.Err
}
