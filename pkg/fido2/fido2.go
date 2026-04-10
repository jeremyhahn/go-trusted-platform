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

package fido2

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Handler provides high-level FIDO2 operations for LUKS unlock
type Handler interface {
	// EnrollKey enrolls a FIDO2 key for LUKS
	EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error)

	// UnlockWithKey unlocks using FIDO2 and returns the derived key
	UnlockWithKey(config *AuthenticationConfig) ([]byte, error)

	// ListDevices returns available FIDO2 devices
	ListDevices() ([]Device, error)

	// WaitForDevice waits for device insertion
	WaitForDevice(ctx context.Context) (*Device, error)

	// Close closes the handler and releases resources
	Close() error
}

// FIDO2Handler implements the Handler interface
type FIDO2Handler struct {
	config     *Config
	enumerator HIDDeviceEnumerator
}

// NewHandler creates a new FIDO2 handler
func NewHandler(config *Config, enumerator HIDDeviceEnumerator) (*FIDO2Handler, error) {
	if config == nil {
		cfg := DefaultConfig
		config = &cfg
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if enumerator == nil {
		return nil, fmt.Errorf("HID device enumerator required")
	}

	return &FIDO2Handler{
		config:     config,
		enumerator: enumerator,
	}, nil
}

// EnrollKey enrolls a FIDO2 key for LUKS
func (h *FIDO2Handler) EnrollKey(config *EnrollmentConfig) (*EnrollmentResult, error) {
	// Find a suitable device
	device, err := h.selectDevice()
	if err != nil {
		return nil, err
	}

	// Open CTAP device
	ctapDev, err := NewCTAPHIDDevice(device, h.config)
	if err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("failed to initialize CTAP device: %w", err)
	}
	defer ctapDev.Close()

	// Create authenticator
	auth, err := NewAuthenticator(ctapDev, h.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	// Check for hmac-secret support
	if !auth.SupportsHMACSecret() {
		return nil, fmt.Errorf("device does not support hmac-secret extension")
	}

	// Create HMAC-secret extension handler
	hmacExt, err := NewHMACSecretExtension(auth)
	if err != nil {
		return nil, err
	}

	// Set timeout if specified
	if config.Timeout > 0 {
		originalTimeout := h.config.Timeout
		h.config.Timeout = config.Timeout
		defer func() { h.config.Timeout = originalTimeout }()
	}

	// Enroll credential
	fmt.Println("Please touch your security key...")
	result, err := hmacExt.EnrollCredential(config)
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}

	result.Created = time.Now()
	return result, nil
}

// UnlockWithKey unlocks using FIDO2 and returns the derived LUKS key
func (h *FIDO2Handler) UnlockWithKey(config *AuthenticationConfig) ([]byte, error) {
	// Find device
	device, err := h.selectDevice()
	if err != nil {
		return nil, err
	}

	// Open CTAP device
	ctapDev, err := NewCTAPHIDDevice(device, h.config)
	if err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("failed to initialize CTAP device: %w", err)
	}
	defer ctapDev.Close()

	// Create authenticator
	auth, err := NewAuthenticator(ctapDev, h.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	// Check for hmac-secret support
	if !auth.SupportsHMACSecret() {
		return nil, fmt.Errorf("device does not support hmac-secret extension")
	}

	// Create HMAC-secret extension handler
	hmacExt, err := NewHMACSecretExtension(auth)
	if err != nil {
		return nil, err
	}

	// Set timeout if specified
	if config.Timeout > 0 {
		originalTimeout := h.config.Timeout
		h.config.Timeout = config.Timeout
		defer func() { h.config.Timeout = originalTimeout }()
	}

	// Retry logic for user presence
	var lastErr error
	for attempt := 0; attempt < h.config.RetryCount; attempt++ {
		if attempt > 0 {
			fmt.Printf("Retry %d/%d - ", attempt+1, h.config.RetryCount)
			time.Sleep(h.config.RetryDelay)
		}

		fmt.Println("Please touch your security key...")

		// Derive secret
		result, err := hmacExt.DeriveSecret(config)
		if err != nil {
			lastErr = err
			if err == ErrUserPresenceRequired || err == ErrOperationTimeout {
				continue // Retry
			}
			return nil, err // Non-retriable error
		}

		// Generate LUKS key from HMAC secret
		luksKey, err := GenerateLUKSKey(result.HMACSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to generate LUKS key: %w", err)
		}

		return luksKey, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("unlock failed after %d attempts: %w", h.config.RetryCount, lastErr)
	}

	return nil, fmt.Errorf("unlock failed after %d attempts", h.config.RetryCount)
}

// ListDevices returns available FIDO2 devices
func (h *FIDO2Handler) ListDevices() ([]Device, error) {
	// Enumerate all FIDO2 devices (vendor ID 0, product ID 0 means all)
	hidDevices, err := h.enumerator.Enumerate(0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate devices: %w", err)
	}

	var devices []Device
	for _, hidDev := range hidDevices {
		// Filter for FIDO2 devices if needed
		if h.isFIDO2Device(hidDev) {
			devices = append(devices, Device{
				Path:         hidDev.Path(),
				VendorID:     hidDev.VendorID(),
				ProductID:    hidDev.ProductID(),
				Manufacturer: hidDev.Manufacturer(),
				Product:      hidDev.Product(),
				SerialNumber: hidDev.SerialNumber(),
				Transport:    "usb",
			})
		}
		_ = hidDev.Close()
	}

	return devices, nil
}

// WaitForDevice waits for a FIDO2 device to be inserted
func (h *FIDO2Handler) WaitForDevice(ctx context.Context) (*Device, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			devices, err := h.ListDevices()
			if err != nil {
				continue
			}
			if len(devices) > 0 {
				return &devices[0], nil
			}
		}
	}
}

// selectDevice selects a suitable FIDO2 device
func (h *FIDO2Handler) selectDevice() (HIDDevice, error) {
	// If specific device path is configured, use it
	if h.config.DevicePath != "" {
		device, err := h.enumerator.Open(h.config.DevicePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open configured device %s: %w", h.config.DevicePath, err)
		}
		return device, nil
	}

	// Enumerate devices
	hidDevices, err := h.enumerator.Enumerate(0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate devices: %w", err)
	}

	if len(hidDevices) == 0 {
		return nil, ErrNoDeviceFound
	}

	// Filter and select device
	var selectedDevice HIDDevice
	var closeErrs []error
	for _, device := range hidDevices {
		if !h.isFIDO2Device(device) {
			if cerr := device.Close(); cerr != nil {
				closeErrs = append(closeErrs, cerr)
			}
			continue
		}

		// Apply vendor/product filters if configured
		if len(h.config.AllowedVendors) > 0 {
			allowed := false
			for _, vid := range h.config.AllowedVendors {
				if device.VendorID() == vid {
					allowed = true
					break
				}
			}
			if !allowed {
				if cerr := device.Close(); cerr != nil {
					closeErrs = append(closeErrs, cerr)
				}
				continue
			}
		}

		if len(h.config.AllowedProducts) > 0 {
			allowed := false
			for _, pid := range h.config.AllowedProducts {
				if device.ProductID() == pid {
					allowed = true
					break
				}
			}
			if !allowed {
				if cerr := device.Close(); cerr != nil {
					closeErrs = append(closeErrs, cerr)
				}
				continue
			}
		}

		// Use first matching device
		selectedDevice = device
		break
	}

	// Close remaining devices
	for _, device := range hidDevices {
		if device != selectedDevice {
			if cerr := device.Close(); cerr != nil {
				closeErrs = append(closeErrs, cerr)
			}
		}
	}

	if selectedDevice == nil {
		if len(closeErrs) > 0 {
			return nil, errors.Join(append([]error{ErrNoDeviceFound}, closeErrs...)...)
		}
		return nil, ErrNoDeviceFound
	}

	return selectedDevice, nil
}

// isFIDO2Device checks if a HID device is a FIDO2 authenticator
func (h *FIDO2Handler) isFIDO2Device(device HIDDevice) bool {
	// FIDO2 devices use HID usage page 0xF1D0
	// This is a simplified check - proper implementation would query HID descriptor
	// For now, we'll accept any device and let CTAP initialization fail if not FIDO2
	return true
}

// Close closes the handler and releases resources
func (h *FIDO2Handler) Close() error {
	// Nothing to clean up in the handler itself
	return nil
}

// DefaultEnrollmentConfig creates a default enrollment configuration for LUKS
func DefaultEnrollmentConfig(userName string) *EnrollmentConfig {
	return &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   DefaultConfig.RelyingPartyID,
			Name: DefaultConfig.RelyingPartyName,
		},
		User: User{
			Name:        userName,
			DisplayName: userName,
		},
		RequireUserVerification: false,
		Timeout:                 DefaultUserPresenceTimeout,
	}
}

// DefaultAuthenticationConfig creates a default authentication configuration for LUKS
func DefaultAuthenticationConfig(credentialID, salt []byte) *AuthenticationConfig {
	return &AuthenticationConfig{
		RelyingPartyID:          DefaultConfig.RelyingPartyID,
		CredentialID:            credentialID,
		Salt:                    salt,
		RequireUserVerification: false,
		Timeout:                 DefaultUserPresenceTimeout,
	}
}
