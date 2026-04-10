package entities

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeviceState_String(t *testing.T) {
	tests := []struct {
		state    DeviceState
		expected string
	}{
		{DeviceStateUnknown, "unknown"},
		{DeviceStateRegistered, "registered"},
		{DeviceStateActivated, "activated"},
		{DeviceStateAttested, "attested"},
		{DeviceStateSuspended, "suspended"},
		{DeviceStateRevoked, "revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestDeviceState_IsValid(t *testing.T) {
	tests := []struct {
		state DeviceState
		valid bool
	}{
		{DeviceStateUnknown, true},
		{DeviceStateRegistered, true},
		{DeviceStateActivated, true},
		{DeviceStateAttested, true},
		{DeviceStateSuspended, true},
		{DeviceStateRevoked, true},
		{DeviceState("invalid"), false},
		{DeviceState(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.state.IsValid())
		})
	}
}

func TestDevice_IsActivated(t *testing.T) {
	tests := []struct {
		name     string
		state    DeviceState
		expected bool
	}{
		{"activated", DeviceStateActivated, true},
		{"attested", DeviceStateAttested, true},
		{"registered", DeviceStateRegistered, false},
		{"suspended", DeviceStateSuspended, false},
		{"revoked", DeviceStateRevoked, false},
		{"unknown", DeviceStateUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Device{State: tt.state}
			assert.Equal(t, tt.expected, d.IsActivated())
		})
	}
}

func TestDevice_IsAttested(t *testing.T) {
	tests := []struct {
		state    DeviceState
		expected bool
	}{
		{DeviceStateAttested, true},
		{DeviceStateActivated, false},
		{DeviceStateRegistered, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			d := &Device{State: tt.state}
			assert.Equal(t, tt.expected, d.IsAttested())
		})
	}
}

func TestDevice_CanActivate(t *testing.T) {
	tests := []struct {
		state    DeviceState
		expected bool
	}{
		{DeviceStateRegistered, true},
		{DeviceStateUnknown, true},
		{DeviceStateActivated, false},
		{DeviceStateAttested, false},
		{DeviceStateSuspended, false},
		{DeviceStateRevoked, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			d := &Device{State: tt.state}
			assert.Equal(t, tt.expected, d.CanActivate())
		})
	}
}

func TestDevice_CanAttest(t *testing.T) {
	tests := []struct {
		state    DeviceState
		expected bool
	}{
		{DeviceStateActivated, true},
		{DeviceStateAttested, true},
		{DeviceStateRegistered, false},
		{DeviceStateUnknown, false},
		{DeviceStateSuspended, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			d := &Device{State: tt.state}
			assert.Equal(t, tt.expected, d.CanAttest())
		})
	}
}

func TestDevice_TenantID(t *testing.T) {
	d := &Device{TenantID: "tenant-123"}
	assert.Equal(t, "tenant-123", d.TenantID)
}

func TestDevice_StateTracking(t *testing.T) {
	now := time.Now()
	d := &Device{
		ID:              1,
		State:           DeviceStateActivated,
		StateReason:     "initial activation",
		ActivatedAt:     now,
		LastAttestedAt:  now.Add(-1 * time.Hour),
		LastHeartbeatAt: now.Add(-5 * time.Minute),
		CreatedAt:       now.Add(-24 * time.Hour),
		UpdatedAt:       now,
	}

	assert.Equal(t, DeviceStateActivated, d.State)
	assert.Equal(t, "initial activation", d.StateReason)
	assert.False(t, d.ActivatedAt.IsZero())
	assert.False(t, d.LastAttestedAt.IsZero())
	assert.False(t, d.LastHeartbeatAt.IsZero())
}
