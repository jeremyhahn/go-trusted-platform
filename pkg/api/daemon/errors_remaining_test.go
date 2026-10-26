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

package daemon

import (
	"errors"
	"testing"
)

func TestErrServiceUnavailable(t *testing.T) {
	err := ErrServiceUnavailable{Service: "kms"}
	expected := "service unavailable: kms"
	if got := err.Error(); got != expected {
		t.Errorf("ErrServiceUnavailable.Error() = %q, want %q", got, expected)
	}

	var target ErrServiceUnavailable
	if !errors.As(err, &target) {
		t.Error("expected errors.As to match ErrServiceUnavailable")
	}
	if target.Service != "kms" {
		t.Errorf("expected Service=kms, got %s", target.Service)
	}
}

func TestErrDeviceOperationFailed(t *testing.T) {
	cause := errors.New("disk full")
	err := ErrDeviceOperationFailed{Operation: "save", Cause: cause}
	expected := "device operation save failed: disk full"
	if got := err.Error(); got != expected {
		t.Errorf("ErrDeviceOperationFailed.Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrDeviceProfileServiceNotAvailable(t *testing.T) {
	err := ErrDeviceProfileServiceNotAvailable{}
	expected := "device: profile service not available"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrKMSOperationNotImplemented(t *testing.T) {
	err := ErrKMSOperationNotImplemented{Operation: "Encrypt"}
	expected := "KMS operation not implemented: Encrypt"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrInvalidCertificatePEM(t *testing.T) {
	err := ErrInvalidCertificatePEM{}
	expected := "invalid PEM-encoded certificate"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrTPM2ServiceNotAvailable(t *testing.T) {
	err := ErrTPM2ServiceNotAvailable{}
	expected := "TPM2 service not available"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIDevIDNotFound(t *testing.T) {
	err := ErrIDevIDNotFound{}
	expected := "IDevID not found in TPM"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAKNotFound(t *testing.T) {
	err := ErrIAKNotFound{}
	expected := "IAK not found in TPM"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIDevIDCertificateNotFound(t *testing.T) {
	err := ErrIDevIDCertificateNotFound{}
	expected := "IDevID certificate not installed"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAKCertificateNotFound(t *testing.T) {
	err := ErrIAKCertificateNotFound{}
	expected := "IAK certificate not installed"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrTPM2OperationFailed(t *testing.T) {
	cause := errors.New("device busy")
	err := ErrTPM2OperationFailed{Operation: "seal", Cause: cause}
	expected := "TPM2 operation seal failed: device busy"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrContainerServiceNotAvailable(t *testing.T) {
	err := ErrContainerServiceNotAvailable{}
	expected := "container service not available"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrContainerNotFound(t *testing.T) {
	err := ErrContainerNotFound{ContainerID: "abc123"}
	expected := "container not found: abc123"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrContainerOperationFailed(t *testing.T) {
	cause := errors.New("network error")
	err := ErrContainerOperationFailed{Operation: "start", Cause: cause}
	expected := "container operation start failed: network error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrContainerAttestNotSupported(t *testing.T) {
	err := ErrContainerAttestNotSupported{}
	expected := "container attestation not implemented"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrContainerInvalidParameter(t *testing.T) {
	err := ErrContainerInvalidParameter{Parameter: "image", Reason: "empty"}
	expected := "invalid container parameter image: empty"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrQuicBaaSServiceUnavailable(t *testing.T) {
	err := ErrQuicBaaSServiceUnavailable{}
	expected := "QuicBaaS service not available for authentication"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrTokenValidationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("expired")
		err := ErrTokenValidationFailed{Cause: cause}
		expected := "token validation failed: expired"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %q, want %q", got, expected)
		}
		if unwrapped := err.Unwrap(); unwrapped != cause {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrTokenValidationFailed{}
		expected := "token validation failed"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %q, want %q", got, expected)
		}
		if unwrapped := err.Unwrap(); unwrapped != nil {
			t.Errorf("Unwrap() = %v, want nil", unwrapped)
		}
	})
}

func TestErrOverlayServiceNotAvailable(t *testing.T) {
	err := ErrOverlayServiceNotAvailable{}
	expected := "overlay network service not available"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrGatewayServiceNotAvailable(t *testing.T) {
	err := ErrGatewayServiceNotAvailable{}
	expected := "gateway service not available"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrTPMInvalidSize(t *testing.T) {
	err := ErrTPMInvalidSize{Max: 1024, Requested: 2048}
	expected := "requested size 2048 exceeds maximum 1024 bytes"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrTenantDEKProvision(t *testing.T) {
	cause := errors.New("kms down")
	err := ErrTenantDEKProvision{TenantID: "tenant-1", Cause: cause}
	expected := "daemon: failed to provision DEK for tenant tenant-1: kms down"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrTenantDEKDeprovision(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrTenantDEKDeprovision{TenantID: "tenant-2", Cause: cause}
	expected := "daemon: failed to deprovision DEK for tenant tenant-2: timeout"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}
