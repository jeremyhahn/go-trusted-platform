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

package app

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// ---------------------------------------------------------------------------
// inlineRestorer satisfies the anonymous interface in restoreCore.restorer.
// ---------------------------------------------------------------------------

// inlineRestorer implements the anonymous interface required by restoreCore:
//
//	interface {
//	    RestoreFactoryCertificate(ctx context.Context) (*x509.Certificate, error)
//	    Close() error
//	}
type inlineRestorer struct {
	cert       *x509.Certificate
	restoreErr error
	closed     bool
}

// RestoreFactoryCertificate returns cert (or restoreErr when set).
func (r *inlineRestorer) RestoreFactoryCertificate(_ context.Context) (*x509.Certificate, error) {
	if r.restoreErr != nil {
		return nil, r.restoreErr
	}
	return r.cert, nil
}

// Close marks the restorer as closed.
func (r *inlineRestorer) Close() error {
	r.closed = true
	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// minimalRestoreCore returns a restoreCore with working device loader/saver fakes.
func minimalRestoreCore(t *testing.T) (*restoreCore, *entities.Device) {
	t.Helper()
	dev := &entities.Device{
		ID:    42,
		State: entities.DeviceStateActivated,
		BMCEnrollment: &entities.BMCEnrollment{
			PinSPKISHA256:     "abc123",
			DNSName:           "lab-node-1-bmc.internal.",
			TLSAPublished:     true,
			FactoryCertSHA256: "originalfactory",
		},
	}
	core := &restoreCore{
		deviceLoader: func(_ context.Context, _ uint64) (*entities.Device, error) {
			return dev, nil
		},
		deviceSaver: func(_ context.Context, _ *entities.Device) error {
			return nil
		},
	}
	return core, dev
}

// findRestoreStep locates a step by name and asserts its OK flag.
func findRestoreStep(t *testing.T, result *BMCRestoreResult, name string, wantOK bool) BMCEnrollStep {
	t.Helper()
	for _, s := range result.Steps {
		if s.Name == name {
			if s.OK != wantOK {
				t.Errorf("restore step %q: OK = %v, want %v (detail: %q)", name, s.OK, wantOK, s.Detail)
			}
			return s
		}
	}
	names := make([]string, len(result.Steps))
	for i, s := range result.Steps {
		names[i] = s.Name
	}
	t.Errorf("restore step %q not found in steps %v", name, names)
	return BMCEnrollStep{}
}

// ---------------------------------------------------------------------------
// runRestoreCore tests
// ---------------------------------------------------------------------------

// TestRunRestoreCore_NoCertRestorer verifies that when no restorer is wired
// the ceremony fails on the first step with ErrBMCRestoreNoCertRestorer.
func TestRunRestoreCore_NoCertRestorer(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	core.restorer = nil

	result, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "", core)
	if err == nil {
		t.Fatal("expected error when no restorer is wired")
	}
	var noCertRestorer ErrBMCRestoreNoCertRestorer
	if !errors.As(err, &noCertRestorer) {
		t.Errorf("err = %T(%v), want ErrBMCRestoreNoCertRestorer", err, err)
	}
	if noCertRestorer.DeviceID != 42 {
		t.Errorf("DeviceID = %d, want 42", noCertRestorer.DeviceID)
	}
	findRestoreStep(t, result, "restore-cert", false)
}

// TestRunRestoreCore_RestoreCertFails verifies that a restorer error surfaces
// as ErrBMCRestoreCert with the cause preserved.
func TestRunRestoreCore_RestoreCertFails(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	restoreErr := errors.New("SSL_DEFAULT rejected")
	core.restorer = &inlineRestorer{restoreErr: restoreErr}

	result, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "", core)
	if err == nil {
		t.Fatal("expected ErrBMCRestoreCert")
	}
	var certErr ErrBMCRestoreCert
	if !errors.As(err, &certErr) {
		t.Errorf("err = %T(%v), want ErrBMCRestoreCert", err, err)
	}
	if !errors.Is(certErr.Cause, restoreErr) {
		t.Errorf("ErrBMCRestoreCert.Cause = %v, want %v", certErr.Cause, restoreErr)
	}
	findRestoreStep(t, result, "restore-cert", false)
}

// TestRunRestoreCore_HappyPath verifies the full ceremony completes with all
// four steps OK when no errors are injected.
func TestRunRestoreCore_HappyPath(t *testing.T) {
	core, dev := minimalRestoreCore(t)
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}

	result, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "", core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findRestoreStep(t, result, "restore-cert", true)
	findRestoreStep(t, result, "pin-delete", true)
	findRestoreStep(t, result, "dane-unpublish", true)
	findRestoreStep(t, result, "device-state", true)

	// Enrollment fields cleared.
	if dev.BMCEnrollment.PinSPKISHA256 != "" {
		t.Errorf("PinSPKISHA256 = %q, want empty", dev.BMCEnrollment.PinSPKISHA256)
	}
	if dev.BMCEnrollment.TLSAPublished {
		t.Error("TLSAPublished should be false after restore")
	}
	// Audit field preserved.
	if dev.BMCEnrollment.FactoryCertSHA256 != "originalfactory" {
		t.Errorf("FactoryCertSHA256 = %q, want %q", dev.BMCEnrollment.FactoryCertSHA256, "originalfactory")
	}
}

// TestRunRestoreCore_PinDelete_Called verifies the pinDeleter closure is invoked
// with correct host and port.
func TestRunRestoreCore_PinDelete_Called(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}

	pinCalled := false
	core.pinDeleter = func(_ context.Context, host string, port int) error {
		pinCalled = true
		if host != "bmc.internal" {
			t.Errorf("pinDeleter host = %q, want bmc.internal", host)
		}
		if port != 443 {
			t.Errorf("pinDeleter port = %d, want 443", port)
		}
		return nil
	}

	if _, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "", core); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pinCalled {
		t.Error("pinDeleter was not called")
	}
}

// TestRunRestoreCore_PinDelete_NonFatal verifies that a pinDeleter failure
// is recorded as a non-fatal step and the ceremony continues.
func TestRunRestoreCore_PinDelete_NonFatal(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}
	core.pinDeleter = func(_ context.Context, _ string, _ int) error {
		return errors.New("pin store unavailable")
	}

	result, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "", core)
	if err != nil {
		t.Fatalf("pin-delete error should be non-fatal; got: %v", err)
	}
	findRestoreStep(t, result, "pin-delete", false)
	// Ceremony continues: device-state step should succeed.
	findRestoreStep(t, result, "device-state", true)
}

// TestRunRestoreCore_DANE_NonFatal verifies that a DANE unpublish error
// is recorded as a non-fatal step and the ceremony continues.
func TestRunRestoreCore_DANE_NonFatal(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}
	core.daneUnpublish = func(_ context.Context, _ string, _ uint16, _ string) error {
		return errors.New("DANE DNS timeout")
	}

	result, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "internal.", core)
	if err != nil {
		t.Fatalf("DANE error should be non-fatal; got: %v", err)
	}
	findRestoreStep(t, result, "dane-unpublish", false)
	findRestoreStep(t, result, "device-state", true)
}

// TestRunRestoreCore_DANE_UsesEnrolledDNSName verifies that the TLSA removal
// is keyed by the DNS name the enrollment ceremony published under
// (Device.BMCEnrollment.DNSName, trailing dot stripped), not the raw BMC host.
func TestRunRestoreCore_DANE_UsesEnrolledDNSName(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}
	var gotName string
	var gotPort uint16
	core.daneUnpublish = func(_ context.Context, hostname string, port uint16, _ string) error {
		gotName = hostname
		gotPort = port
		return nil
	}

	result, err := runRestoreCore(context.Background(), 42, "198.51.100.102", "198.51.100.102:443", "internal.", core)
	if err != nil {
		t.Fatalf("runRestoreCore: %v", err)
	}
	if gotName != "lab-node-1-bmc.internal" {
		t.Errorf("dane unpublish hostname = %q, want enrolled DNS name %q", gotName, "lab-node-1-bmc.internal")
	}
	if gotPort != 443 {
		t.Errorf("dane unpublish port = %d, want 443", gotPort)
	}
	findRestoreStep(t, result, "dane-unpublish", true)
}

// TestRunRestoreCore_DANE_SkipsWithoutDNSName verifies that the unpublish step
// is skipped when the enrollment record carries no DNS name (enrollment never
// registered DNS, so there is nothing to remove).
func TestRunRestoreCore_DANE_SkipsWithoutDNSName(t *testing.T) {
	core, dev := minimalRestoreCore(t)
	dev.BMCEnrollment.DNSName = ""
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}
	called := false
	core.daneUnpublish = func(_ context.Context, _ string, _ uint16, _ string) error {
		called = true
		return nil
	}

	result, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "internal.", core)
	if err != nil {
		t.Fatalf("runRestoreCore: %v", err)
	}
	if called {
		t.Error("daneUnpublish must not be called when enrollment has no DNS name")
	}
	findRestoreStep(t, result, "dane-unpublish", true)
}

// TestRunRestoreCore_DeviceLoad_Fails verifies ErrBMCEnrollDeviceLoad is
// returned when the device cannot be loaded for the state-update step.
func TestRunRestoreCore_DeviceLoad_Fails(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}
	core.deviceLoader = func(_ context.Context, _ uint64) (*entities.Device, error) {
		return nil, errors.New("device not found")
	}

	_, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "", core)
	if err == nil {
		t.Fatal("expected error from device load failure")
	}
	var devLoadErr ErrBMCEnrollDeviceLoad
	if !errors.As(err, &devLoadErr) {
		t.Errorf("err = %T(%v), want ErrBMCEnrollDeviceLoad", err, err)
	}
}

// TestRunRestoreCore_DeviceSave_Fails verifies ErrBMCEnrollDeviceSave is
// returned when the device cannot be saved after the enrollment is cleared.
func TestRunRestoreCore_DeviceSave_Fails(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	core.restorer = &inlineRestorer{cert: testIssuedCertificate()}
	core.deviceSaver = func(_ context.Context, _ *entities.Device) error {
		return errors.New("storage write failed")
	}

	_, err := runRestoreCore(context.Background(), 42, "bmc.internal", "bmc.internal:443", "", core)
	if err == nil {
		t.Fatal("expected error from device save failure")
	}
	var devSaveErr ErrBMCEnrollDeviceSave
	if !errors.As(err, &devSaveErr) {
		t.Errorf("err = %T(%v), want ErrBMCEnrollDeviceSave", err, err)
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

// TestErrBMCRestoreNoCertRestorer_Message verifies the error message is non-empty.
func TestErrBMCRestoreNoCertRestorer_Message(t *testing.T) {
	e := ErrBMCRestoreNoCertRestorer{DeviceID: 99}
	if e.Error() == "" {
		t.Error("empty error message")
	}
}

// TestErrBMCRestoreCert_Unwrap verifies Unwrap returns the cause.
func TestErrBMCRestoreCert_Unwrap(t *testing.T) {
	cause := errors.New("SSL_DEFAULT failed")
	e := ErrBMCRestoreCert{DeviceID: 7, Cause: cause}
	if e.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), cause)
	}
	if e.Error() == "" {
		t.Error("empty error message")
	}
}

// TestRunRestoreCore_InlineRestorer_Close verifies the restorer is always closed.
func TestRunRestoreCore_InlineRestorer_Close(t *testing.T) {
	core, _ := minimalRestoreCore(t)
	restorer := &inlineRestorer{cert: testIssuedCertificate()}
	core.restorer = restorer

	if _, err := runRestoreCore(context.Background(), 42, "h", "h:443", "", core); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !restorer.closed {
		t.Error("restorer.Close() was not called")
	}
}
