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

package pxe

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProvisioningState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    ProvisioningState
		expected string
	}{
		{"unknown", StateUnknown, "unknown"},
		{"discovered", StateDiscovered, "discovered"},
		{"booting", StateBooting, "booting"},
		{"installing", StateInstalling, "installing"},
		{"install_complete", StateInstallComplete, "install_complete"},
		{"enrolling", StateEnrolling, "enrolling"},
		{"enrolled", StateEnrolled, "enrolled"},
		{"authorizing", StateAuthorizing, "authorizing"},
		{"authorized", StateAuthorized, "authorized"},
		{"failed", StateFailed, "failed"},
		{"quarantined", StateQuarantined, "quarantined"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestProvisioningState_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		state    ProvisioningState
		expected bool
	}{
		{"valid_unknown", StateUnknown, true},
		{"valid_discovered", StateDiscovered, true},
		{"valid_booting", StateBooting, true},
		{"valid_installing", StateInstalling, true},
		{"valid_install_complete", StateInstallComplete, true},
		{"valid_enrolling", StateEnrolling, true},
		{"valid_enrolled", StateEnrolled, true},
		{"valid_authorizing", StateAuthorizing, true},
		{"valid_authorized", StateAuthorized, true},
		{"valid_failed", StateFailed, true},
		{"valid_quarantined", StateQuarantined, true},
		{"invalid_empty", ProvisioningState(""), false},
		{"invalid_random", ProvisioningState("invalid_state"), false},
		{"invalid_wrong_case", ProvisioningState("Discovered"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.IsValid())
		})
	}
}

func TestProvisioningState_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		state    ProvisioningState
		expected bool
	}{
		{"terminal_authorized", StateAuthorized, true},
		{"terminal_failed", StateFailed, true},
		{"terminal_quarantined", StateQuarantined, true},
		{"non_terminal_unknown", StateUnknown, false},
		{"non_terminal_discovered", StateDiscovered, false},
		{"non_terminal_booting", StateBooting, false},
		{"non_terminal_installing", StateInstalling, false},
		{"non_terminal_install_complete", StateInstallComplete, false},
		{"non_terminal_enrolling", StateEnrolling, false},
		{"non_terminal_enrolled", StateEnrolled, false},
		{"non_terminal_authorizing", StateAuthorizing, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.IsTerminal())
		})
	}
}

func TestProvisioningState_CanTransitionTo(t *testing.T) {
	tests := []struct {
		name     string
		from     ProvisioningState
		to       ProvisioningState
		expected bool
	}{
		// Valid transitions from Unknown
		{"unknown_to_discovered", StateUnknown, StateDiscovered, true},
		{"unknown_to_failed", StateUnknown, StateFailed, true},
		{"unknown_to_quarantined", StateUnknown, StateQuarantined, true},
		{"unknown_to_booting", StateUnknown, StateBooting, false},

		// Valid transitions from Discovered
		{"discovered_to_booting", StateDiscovered, StateBooting, true},
		{"discovered_to_failed", StateDiscovered, StateFailed, true},
		{"discovered_to_quarantined", StateDiscovered, StateQuarantined, true},
		{"discovered_to_authorized", StateDiscovered, StateAuthorized, false},

		// Valid transitions from Booting
		{"booting_to_installing", StateBooting, StateInstalling, true},
		{"booting_to_failed", StateBooting, StateFailed, true},
		{"booting_to_quarantined", StateBooting, StateQuarantined, true},
		{"booting_to_discovered", StateBooting, StateDiscovered, false},

		// Valid transitions from Installing
		{"installing_to_install_complete", StateInstalling, StateInstallComplete, true},
		{"installing_to_failed", StateInstalling, StateFailed, true},
		{"installing_to_quarantined", StateInstalling, StateQuarantined, true},
		{"installing_to_booting", StateInstalling, StateBooting, false},

		// Valid transitions from InstallComplete
		{"install_complete_to_enrolling", StateInstallComplete, StateEnrolling, true},
		{"install_complete_to_failed", StateInstallComplete, StateFailed, true},
		{"install_complete_to_quarantined", StateInstallComplete, StateQuarantined, true},
		{"install_complete_to_installing", StateInstallComplete, StateInstalling, false},

		// Valid transitions from Enrolling
		{"enrolling_to_enrolled", StateEnrolling, StateEnrolled, true},
		{"enrolling_to_failed", StateEnrolling, StateFailed, true},
		{"enrolling_to_quarantined", StateEnrolling, StateQuarantined, true},
		{"enrolling_to_authorizing", StateEnrolling, StateAuthorizing, false},

		// Valid transitions from Enrolled
		{"enrolled_to_authorizing", StateEnrolled, StateAuthorizing, true},
		{"enrolled_to_failed", StateEnrolled, StateFailed, true},
		{"enrolled_to_quarantined", StateEnrolled, StateQuarantined, true},
		{"enrolled_to_authorized", StateEnrolled, StateAuthorized, false},

		// Valid transitions from Authorizing
		{"authorizing_to_authorized", StateAuthorizing, StateAuthorized, true},
		{"authorizing_to_failed", StateAuthorizing, StateFailed, true},
		{"authorizing_to_quarantined", StateAuthorizing, StateQuarantined, true},
		{"authorizing_to_enrolled", StateAuthorizing, StateEnrolled, false},

		// Valid transitions from Authorized (terminal state)
		{"authorized_to_quarantined", StateAuthorized, StateQuarantined, true},
		{"authorized_to_failed", StateAuthorized, StateFailed, false},
		{"authorized_to_discovered", StateAuthorized, StateDiscovered, false},

		// Valid transitions from Failed
		{"failed_to_discovered", StateFailed, StateDiscovered, true},
		{"failed_to_quarantined", StateFailed, StateQuarantined, true},
		{"failed_to_authorized", StateFailed, StateAuthorized, false},

		// Valid transitions from Quarantined
		{"quarantined_to_discovered", StateQuarantined, StateDiscovered, true},
		{"quarantined_to_authorized", StateQuarantined, StateAuthorized, false},

		// Invalid state as source
		{"invalid_source_state", ProvisioningState("invalid"), StateDiscovered, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.from.CanTransitionTo(tt.to))
		})
	}
}

func TestProvisioningEventType_String(t *testing.T) {
	tests := []struct {
		name      string
		eventType ProvisioningEventType
		expected  string
	}{
		{"device_discovered", EventDeviceDiscovered, "device_discovered"},
		{"pxe_boot_started", EventPXEBootStarted, "pxe_boot_started"},
		{"install_started", EventInstallStarted, "install_started"},
		{"install_completed", EventInstallCompleted, "install_completed"},
		{"enrollment_started", EventEnrollmentStarted, "enrollment_started"},
		{"enrollment_completed", EventEnrollmentCompleted, "enrollment_completed"},
		{"authorization_started", EventAuthorizationStarted, "authorization_started"},
		{"authorization_completed", EventAuthorizationCompleted, "authorization_completed"},
		{"quarantined", EventQuarantined, "quarantined"},
		{"failed", EventFailed, "failed"},
		{"retry", EventRetry, "retry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.eventType.String())
		})
	}
}

func TestProvisioningEventType_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		eventType ProvisioningEventType
		expected  bool
	}{
		{"valid_device_discovered", EventDeviceDiscovered, true},
		{"valid_pxe_boot_started", EventPXEBootStarted, true},
		{"valid_install_started", EventInstallStarted, true},
		{"valid_install_completed", EventInstallCompleted, true},
		{"valid_enrollment_started", EventEnrollmentStarted, true},
		{"valid_enrollment_completed", EventEnrollmentCompleted, true},
		{"valid_authorization_started", EventAuthorizationStarted, true},
		{"valid_authorization_completed", EventAuthorizationCompleted, true},
		{"valid_quarantined", EventQuarantined, true},
		{"valid_failed", EventFailed, true},
		{"valid_retry", EventRetry, true},
		{"invalid_empty", ProvisioningEventType(""), false},
		{"invalid_random", ProvisioningEventType("invalid_event"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.eventType.IsValid())
		})
	}
}

func TestDeviceFilter_Matches(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	now := time.Now()

	device := &DeviceInfo{
		ID:             "device-123",
		MACAddress:     mac,
		PortID:         "port-1",
		State:          StateDiscovered,
		CurrentVLAN:    100,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
	}
	enrolled := copyDeviceInfo(device)
	enrolledFingerprint := CertificateFingerprintOf(&x509.Certificate{Raw: []byte("platform CA/4242")})
	enrolled.CertificateSerial = "4242"
	enrolled.CertificateFingerprint = enrolledFingerprint

	tests := []struct {
		name     string
		filter   *DeviceFilter
		device   *DeviceInfo
		expected bool
	}{
		{
			name:     "nil_device",
			filter:   &DeviceFilter{},
			device:   nil,
			expected: false,
		},
		{
			name:     "empty_filter_matches_all",
			filter:   &DeviceFilter{},
			device:   device,
			expected: true,
		},
		{
			name:     "state_filter_match",
			filter:   &DeviceFilter{State: StateDiscovered},
			device:   device,
			expected: true,
		},
		{
			name:     "state_filter_no_match",
			filter:   &DeviceFilter{State: StateBooting},
			device:   device,
			expected: false,
		},
		{
			name:     "mac_filter_exact_match",
			filter:   &DeviceFilter{MACAddress: "00:11:22:33:44:55"},
			device:   device,
			expected: true,
		},
		{
			name:     "mac_filter_prefix_match",
			filter:   &DeviceFilter{MACAddress: "00:11:22"},
			device:   device,
			expected: true,
		},
		{
			name:     "mac_filter_no_match",
			filter:   &DeviceFilter{MACAddress: "aa:bb:cc:dd:ee:ff"},
			device:   device,
			expected: false,
		},
		{
			name:     "vlan_filter_match",
			filter:   &DeviceFilter{VLAN: 100},
			device:   device,
			expected: true,
		},
		{
			name:     "vlan_filter_no_match",
			filter:   &DeviceFilter{VLAN: 200},
			device:   device,
			expected: false,
		},
		{
			name:     "combined_filters_match",
			filter:   &DeviceFilter{State: StateDiscovered, VLAN: 100},
			device:   device,
			expected: true,
		},
		{
			name:     "combined_filters_partial_match_fails",
			filter:   &DeviceFilter{State: StateDiscovered, VLAN: 200},
			device:   device,
			expected: false,
		},
		{
			name:     "vlan_zero_does_not_filter",
			filter:   &DeviceFilter{VLAN: 0},
			device:   device,
			expected: true,
		},
		{
			name:     "certificate_fingerprint_filter_match",
			filter:   &DeviceFilter{CertificateFingerprint: enrolledFingerprint},
			device:   enrolled,
			expected: true,
		},
		{
			// Exact match only: a fingerprint is not a prefix of another.
			name:     "certificate_fingerprint_filter_no_prefix_match",
			filter:   &DeviceFilter{CertificateFingerprint: enrolledFingerprint[:8]},
			device:   enrolled,
			expected: false,
		},
		{
			// The serial is not the key: an equal serial with another
			// fingerprint (another issuer's certificate) does not match.
			name:     "certificate_fingerprint_filter_ignores_serial",
			filter:   &DeviceFilter{CertificateFingerprint: CertificateFingerprintOf(&x509.Certificate{Raw: []byte("other issuer/4242")})},
			device:   enrolled,
			expected: false,
		},
		{
			name:     "certificate_fingerprint_filter_excludes_unenrolled",
			filter:   &DeviceFilter{CertificateFingerprint: enrolledFingerprint},
			device:   device,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.filter.Matches(tt.device))
		})
	}
}

func TestHasPrefix(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		prefix   string
		expected bool
	}{
		{"exact_match", "hello", "hello", true},
		{"prefix_match", "hello world", "hello", true},
		{"no_match", "hello", "world", false},
		{"empty_prefix", "hello", "", true},
		{"empty_string", "", "hello", false},
		{"both_empty", "", "", true},
		{"prefix_longer_than_string", "hi", "hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasPrefix(tt.s, tt.prefix))
		})
	}
}

func TestDeviceInfo_StructFields(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	now := time.Now()

	device := &DeviceInfo{
		ID:                "device-123",
		MACAddress:        mac,
		PortID:            "port-1",
		State:             StateDiscovered,
		StateReason:       "newly discovered",
		CertificateSerial: "serial-123",
		CurrentVLAN:       100,
		TargetVLAN:        200,
		CreatedAt:         now,
		UpdatedAt:         now,
		StateChangedAt:    now,
		RetryCount:        2,
		Events:            []*ProvisioningEvent{},
	}

	assert.Equal(t, "device-123", device.ID)
	assert.Equal(t, mac, device.MACAddress)
	assert.Equal(t, "port-1", device.PortID)
	assert.Equal(t, StateDiscovered, device.State)
	assert.Equal(t, "newly discovered", device.StateReason)
	assert.Equal(t, "serial-123", device.CertificateSerial)
	assert.Equal(t, uint16(100), device.CurrentVLAN)
	assert.Equal(t, uint16(200), device.TargetVLAN)
	assert.Equal(t, now, device.CreatedAt)
	assert.Equal(t, now, device.UpdatedAt)
	assert.Equal(t, now, device.StateChangedAt)
	assert.Equal(t, 2, device.RetryCount)
	assert.NotNil(t, device.Events)
}

func TestProvisioningEvent_StructFields(t *testing.T) {
	now := time.Now()
	event := &ProvisioningEvent{
		ID:        "event-123",
		DeviceID:  "device-456",
		Timestamp: now,
		EventType: EventDeviceDiscovered,
		FromState: StateUnknown,
		ToState:   StateDiscovered,
		Details:   map[string]string{"key": "value"},
		Error:     "test error",
	}

	assert.Equal(t, "event-123", event.ID)
	assert.Equal(t, "device-456", event.DeviceID)
	assert.Equal(t, now, event.Timestamp)
	assert.Equal(t, EventDeviceDiscovered, event.EventType)
	assert.Equal(t, StateUnknown, event.FromState)
	assert.Equal(t, StateDiscovered, event.ToState)
	assert.Equal(t, "value", event.Details["key"])
	assert.Equal(t, "test error", event.Error)
}

func TestWebhookPayload_StructFields(t *testing.T) {
	now := time.Now()
	payload := &WebhookPayload{
		MACAddress: "00:11:22:33:44:55",
		Hostname:   "host-001",
		Success:    true,
		Message:    "Installation complete",
		Timestamp:  now,
	}

	assert.Equal(t, "00:11:22:33:44:55", payload.MACAddress)
	assert.Equal(t, "host-001", payload.Hostname)
	assert.True(t, payload.Success)
	assert.Equal(t, "Installation complete", payload.Message)
	assert.Equal(t, now, payload.Timestamp)
}

func TestServiceStatus_StructFields(t *testing.T) {
	now := time.Now()
	status := &ServiceStatus{
		Running:          true,
		DeviceCount:      10,
		StartTime:        now,
		IPXEServerAddr:   "192.168.1.1",
		QuarantineVLAN:   1,
		ProvisioningVLAN: 2,
	}

	assert.True(t, status.Running)
	assert.Equal(t, 10, status.DeviceCount)
	assert.Equal(t, now, status.StartTime)
	assert.Equal(t, "192.168.1.1", status.IPXEServerAddr)
	assert.Equal(t, uint16(1), status.QuarantineVLAN)
	assert.Equal(t, uint16(2), status.ProvisioningVLAN)
}
