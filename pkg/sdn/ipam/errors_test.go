// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

func TestErrAllocationFailed_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *ErrAllocationFailed
		wantMsg string
	}{
		{
			name: "with cause",
			err: &ErrAllocationFailed{
				PoolID: "pool-1",
				Reason: "pool exhausted",
				Cause:  ErrPoolExhausted,
			},
			wantMsg: "allocation failed for pool pool-1: pool exhausted: pool exhausted",
		},
		{
			name: "without cause",
			err: &ErrAllocationFailed{
				PoolID: "pool-1",
				Reason: "invalid request",
			},
			wantMsg: "allocation failed for pool pool-1: invalid request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("ErrAllocationFailed.Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestErrAllocationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &ErrAllocationFailed{
		PoolID: "pool-1",
		Reason: "test",
		Cause:  cause,
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrIPConflict_Error(t *testing.T) {
	err := &ErrIPConflict{
		IP:       netip.MustParseAddr("192.168.1.10"),
		DeviceID: "device-1",
	}

	want := "IP 192.168.1.10 already allocated to device device-1"
	if got := err.Error(); got != want {
		t.Errorf("ErrIPConflict.Error() = %v, want %v", got, want)
	}
}

func TestErrPoolOperationFailed_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *ErrPoolOperationFailed
		wantMsg string
	}{
		{
			name: "with cause",
			err: &ErrPoolOperationFailed{
				PoolID:    "pool-1",
				Operation: "create",
				Cause:     ErrPoolAlreadyExists,
			},
			wantMsg: "pool operation create failed for pool pool-1: pool already exists",
		},
		{
			name: "without cause",
			err: &ErrPoolOperationFailed{
				PoolID:    "pool-1",
				Operation: "delete",
			},
			wantMsg: "pool operation delete failed for pool pool-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("ErrPoolOperationFailed.Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestErrInvalidAllocationStatus_Error(t *testing.T) {
	err := &ErrInvalidAllocationStatus{
		Current: AllocationStatusReleased,
		Desired: AllocationStatusActive,
		Reason:  "cannot reactivate released allocation",
	}

	want := "invalid status transition from released to active: cannot reactivate released allocation"
	if got := err.Error(); got != want {
		t.Errorf("ErrInvalidAllocationStatus.Error() = %v, want %v", got, want)
	}
}

func TestErrCIDRMismatch_Error(t *testing.T) {
	tests := []struct {
		name string
		ip   netip.Addr
		cidr netip.Prefix
		want string
	}{
		{
			name: "IPv4 IP with IPv6 CIDR",
			ip:   netip.MustParseAddr("192.168.1.1"),
			cidr: netip.MustParsePrefix("2001:db8::/32"),
			want: "IP 192.168.1.1 (IPv4) does not match CIDR 2001:db8::/32 (IPv6) address family",
		},
		{
			name: "IPv6 IP with IPv4 CIDR",
			ip:   netip.MustParseAddr("2001:db8::1"),
			cidr: netip.MustParsePrefix("192.168.1.0/24"),
			want: "IP 2001:db8::1 (IPv6) does not match CIDR 192.168.1.0/24 (IPv4) address family",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ErrCIDRMismatch{IP: tt.ip, CIDR: tt.cidr}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrCIDRMismatch.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrPoolTooLarge_Error(t *testing.T) {
	err := &ErrPoolTooLarge{CIDR: netip.MustParsePrefix("2001:db8::/64"), Max: 16}

	want := "pool 2001:db8::/64 is larger than the 16 addresses this backend can track"
	if got := err.Error(); got != want {
		t.Errorf("ErrPoolTooLarge.Error() = %v, want %v", got, want)
	}
}

func TestErrLeaseExpired_Error(t *testing.T) {
	err := &ErrLeaseExpired{
		IP:        netip.MustParseAddr("192.168.1.10"),
		ExpiredAt: "2024-01-01T00:00:00Z",
	}

	want := "lease for IP 192.168.1.10 expired at 2024-01-01T00:00:00Z"
	if got := err.Error(); got != want {
		t.Errorf("ErrLeaseExpired.Error() = %v, want %v", got, want)
	}
}

func TestIsPoolError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"pool not found", ErrPoolNotFound, true},
		{"pool already exists", ErrPoolAlreadyExists, true},
		{"pool exhausted", ErrPoolExhausted, true},
		{"pool name exists", ErrPoolNameExists, true},
		{"pool CIDR overlaps", ErrPoolCIDROverlaps, true},
		{"pool has allocations", ErrPoolHasAllocations, true},
		{"unrelated error", ErrInvalidIP, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPoolError(tt.err); got != tt.want {
				t.Errorf("IsPoolError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAllocationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"allocation not found", ErrAllocationNotFound, true},
		{"IP already allocated", ErrIPAlreadyAllocated, true},
		{"IP not in pool", ErrIPNotInPool, true},
		{"allocation expired", ErrAllocationExpired, true},
		{"allocation released", ErrAllocationReleased, true},
		{"unrelated error", ErrPoolNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAllocationError(tt.err); got != tt.want {
				t.Errorf("IsAllocationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"invalid CIDR", ErrInvalidCIDR, true},
		{"invalid IP", ErrInvalidIP, true},
		{"invalid gateway", ErrInvalidGateway, true},
		{"invalid pool ID", ErrInvalidPoolID, true},
		{"invalid pool name", ErrInvalidPoolName, true},
		{"invalid offset", ErrInvalidOffset, true},
		{"device ID required", ErrDeviceIDRequired, true},
		{"pool ID required", ErrPoolIDRequired, true},
		{"invalid bitmap data", ErrInvalidBitmapData, true},
		{"pool too large", &ErrPoolTooLarge{CIDR: netip.MustParsePrefix("2001:db8::/64"), Max: 16}, true},
		{"unrelated error", ErrPoolNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidationError(tt.err); got != tt.want {
				t.Errorf("IsValidationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBackendError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"backend unavailable", ErrBackendUnavailable, true},
		{"backend timeout", ErrBackendTimeout, true},
		{"CAS conflict", ErrCASConflict, true},
		{"max retries exceeded", ErrMaxRetriesExceeded, true},
		{"unrelated error", ErrPoolNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBackendError(tt.err); got != tt.want {
				t.Errorf("IsBackendError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrStorageOperation_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *ErrStorageOperation
		wantMsg string
	}{
		{
			name: "with cause",
			err: &ErrStorageOperation{
				Operation: "get",
				Key:       "pool:pool-1",
				Cause:     errors.New("connection refused"),
			},
			wantMsg: "storage operation get failed for key pool:pool-1: connection refused",
		},
		{
			name: "without cause",
			err: &ErrStorageOperation{
				Operation: "put",
				Key:       "alloc:192.168.1.10",
			},
			wantMsg: "storage operation put failed for key alloc:192.168.1.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("ErrStorageOperation.Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestErrSerialization_Error(t *testing.T) {
	err := &ErrSerialization{
		EntityType: "Pool",
		Operation:  "marshal",
		Cause:      errors.New("invalid JSON"),
	}

	want := "marshal failed for Pool: invalid JSON"
	if got := err.Error(); got != want {
		t.Errorf("ErrSerialization.Error() = %v, want %v", got, want)
	}
}
