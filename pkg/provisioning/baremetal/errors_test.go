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

package baremetal

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestErrProvisionNotFound_Error(t *testing.T) {
	err := ErrProvisionNotFound{ProvisionID: "abc123"}
	if !strings.Contains(err.Error(), "abc123") {
		t.Errorf("expected provision ID in error, got: %s", err.Error())
	}
}

func TestErrProvisionNotFound_Type(t *testing.T) {
	var err error = ErrProvisionNotFound{ProvisionID: "abc123"}
	var target ErrProvisionNotFound
	if !errors.As(err, &target) {
		t.Error("expected errors.As to succeed for ErrProvisionNotFound")
	}
}

func TestErrProfileNoBMC_Error(t *testing.T) {
	err := ErrProfileNoBMC{ProfileID: 42}
	if !strings.Contains(err.Error(), "42") {
		t.Errorf("expected profile ID in error, got: %s", err.Error())
	}
}

func TestErrProfileNoBMC_Type(t *testing.T) {
	var err error = ErrProfileNoBMC{ProfileID: 42}
	var target ErrProfileNoBMC
	if !errors.As(err, &target) {
		t.Error("expected errors.As to succeed for ErrProfileNoBMC")
	}
}

func TestErrProvisionInProgress_Error(t *testing.T) {
	err := ErrProvisionInProgress{ProfileID: 7}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("expected profile ID in error, got: %s", err.Error())
	}
}

func TestErrProvisionInProgress_Type(t *testing.T) {
	var err error = ErrProvisionInProgress{ProfileID: 7}
	var target ErrProvisionInProgress
	if !errors.As(err, &target) {
		t.Error("expected errors.As to succeed for ErrProvisionInProgress")
	}
}

func TestErrProvisionFailed_Error(t *testing.T) {
	cause := errors.New("disk full")
	err := ErrProvisionFailed{ProfileID: 1, Step: "mount_iso", Cause: cause}
	msg := err.Error()
	if !strings.Contains(msg, "mount_iso") {
		t.Errorf("expected step in error, got: %s", msg)
	}
	if !strings.Contains(msg, "disk full") {
		t.Errorf("expected cause in error, got: %s", msg)
	}
}

func TestErrProvisionFailed_Unwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrProvisionFailed{ProfileID: 1, Step: "connect", Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("Unwrap did not return the cause")
	}
}

func TestErrProvisionFailed_NilCause(t *testing.T) {
	err := ErrProvisionFailed{ProfileID: 1, Step: "connect"}
	if strings.Contains(err.Error(), "<nil>") {
		t.Error("nil cause should not appear in error message")
	}
}

func TestErrInstallTimeout_Error(t *testing.T) {
	err := ErrInstallTimeout{ProfileID: 5, Timeout: 30 * time.Minute}
	msg := err.Error()
	if !strings.Contains(msg, "5") {
		t.Errorf("expected profile ID in error, got: %s", msg)
	}
	if !strings.Contains(msg, "30m") {
		t.Errorf("expected timeout in error, got: %s", msg)
	}
}

func TestErrInstallTimeout_Type(t *testing.T) {
	var err error = ErrInstallTimeout{ProfileID: 5, Timeout: time.Minute}
	var target ErrInstallTimeout
	if !errors.As(err, &target) {
		t.Error("expected errors.As to succeed for ErrInstallTimeout")
	}
}

func TestErrInvalidProvisionRequest_Error(t *testing.T) {
	err := ErrInvalidProvisionRequest{Reason: "missing profile"}
	if !strings.Contains(err.Error(), "missing profile") {
		t.Errorf("expected reason in error, got: %s", err.Error())
	}
}

func TestErrInvalidProvisionRequest_Type(t *testing.T) {
	var err error = ErrInvalidProvisionRequest{Reason: "test"}
	var target ErrInvalidProvisionRequest
	if !errors.As(err, &target) {
		t.Error("expected errors.As to succeed for ErrInvalidProvisionRequest")
	}
}
