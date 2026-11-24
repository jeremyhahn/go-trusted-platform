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
	"errors"
	"strings"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const testMAC = "02:00:00:00:00:01"

func TestRegister_SendsMACAndPort(t *testing.T) {
	fake := &fakePXEClient{}
	out, err := run(t, fake, "register", "--mac", testMAC, "--port", "port-1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if fake.registerReq == nil {
		t.Fatal("RegisterDevice was not called")
	}
	if got := fake.registerReq.GetMacAddress(); got != testMAC {
		t.Errorf("mac_address = %q, want %q", got, testMAC)
	}
	if got := fake.registerReq.GetPortId(); got != "port-1" {
		t.Errorf("port_id = %q, want port-1", got)
	}
	if !strings.Contains(out, testMAC) {
		t.Errorf("output does not show the MAC:\n%s", out)
	}
}

func TestRegister_RequiresValidMAC(t *testing.T) {
	for _, args := range [][]string{
		{"register"},
		{"register", "--mac", "not-a-mac"},
	} {
		fake := &fakePXEClient{}
		_, err := run(t, fake, args...)
		var target *ErrInvalidMAC
		if !errors.As(err, &target) {
			t.Errorf("%v: err = %v, want *ErrInvalidMAC", args, err)
		}
		if fake.calls != 0 {
			t.Errorf("%v: %d RPCs made, want none", args, fake.calls)
		}
	}
}

func TestRemove_SendsDeviceID(t *testing.T) {
	fake := &fakePXEClient{}
	out, err := run(t, fake, "remove", "dev-1")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if fake.removeReq == nil || fake.removeReq.GetDeviceId() != "dev-1" {
		t.Fatalf("RemoveDevice request = %v, want device_id dev-1", fake.removeReq)
	}
	if !strings.Contains(out, "REMOVED") || !strings.Contains(out, "dev-1") {
		t.Errorf("output does not show the removal:\n%s", out)
	}

	fake = &fakePXEClient{}
	_, err = run(t, fake, "remove", "")
	var target *ErrDeviceIDRequired
	if !errors.As(err, &target) {
		t.Errorf("remove \"\": err = %v, want *ErrDeviceIDRequired", err)
	}
	if fake.calls != 0 {
		t.Errorf("remove \"\": %d RPCs made, want none", fake.calls)
	}
}

func TestGetByMAC_SendsMAC(t *testing.T) {
	fake := &fakePXEClient{}
	out, err := run(t, fake, "get-by-mac", testMAC)
	if err != nil {
		t.Fatalf("get-by-mac: %v", err)
	}
	if fake.getByMACReq == nil || fake.getByMACReq.GetMacAddress() != testMAC {
		t.Fatalf("GetDeviceByMAC request = %v, want mac_address %s", fake.getByMACReq, testMAC)
	}
	if !strings.Contains(out, testMAC) {
		t.Errorf("output does not show the MAC:\n%s", out)
	}

	fake = &fakePXEClient{}
	_, err = run(t, fake, "get-by-mac", "not-a-mac")
	var target *ErrInvalidMAC
	if !errors.As(err, &target) {
		t.Errorf("get-by-mac not-a-mac: err = %v, want *ErrInvalidMAC", err)
	}
	if fake.calls != 0 {
		t.Errorf("get-by-mac not-a-mac: %d RPCs made, want none", fake.calls)
	}
}

func TestSetState_SendsStateAndReason(t *testing.T) {
	fake := &fakePXEClient{}
	out, err := run(t, fake, "set-state", "dev-1", "--state", "booting", "--reason", "re-image")
	if err != nil {
		t.Fatalf("set-state: %v", err)
	}
	req := fake.setStateReq
	if req == nil {
		t.Fatal("UpdateState was not called")
	}
	if req.GetDeviceId() != "dev-1" {
		t.Errorf("device_id = %q, want dev-1", req.GetDeviceId())
	}
	if req.GetState() != platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING {
		t.Errorf("state = %v, want PROVISIONING_STATE_BOOTING", req.GetState())
	}
	if req.GetReason() != "re-image" {
		t.Errorf("reason = %q, want re-image", req.GetReason())
	}
	if !strings.Contains(out, "booting") {
		t.Errorf("output does not show the new state:\n%s", out)
	}
}

func TestSetState_RequiresStateAndReason(t *testing.T) {
	for _, args := range [][]string{
		{"set-state", "dev-1", "--reason", "re-image"},
		{"set-state", "dev-1", "--state", "no-such-state", "--reason", "re-image"},
	} {
		fake := &fakePXEClient{}
		_, err := run(t, fake, args...)
		var target *ErrInvalidState
		if !errors.As(err, &target) {
			t.Errorf("%v: err = %v, want *ErrInvalidState", args, err)
		}
		if fake.calls != 0 {
			t.Errorf("%v: %d RPCs made, want none", args, fake.calls)
		}
	}

	fake := &fakePXEClient{}
	_, err := run(t, fake, "set-state", "dev-1", "--state", "booting")
	var target *ErrReasonRequired
	if !errors.As(err, &target) {
		t.Errorf("set-state without --reason: err = %v, want *ErrReasonRequired", err)
	}
	if fake.calls != 0 {
		t.Errorf("set-state without --reason: %d RPCs made, want none", fake.calls)
	}
}

func TestSetEnrolled_SendsSerial(t *testing.T) {
	fake := &fakePXEClient{}
	out, err := run(t, fake, "set-enrolled", "dev-1", "--certificate-serial", "0a1b")
	if err != nil {
		t.Fatalf("set-enrolled: %v", err)
	}
	req := fake.enrolledReq
	if req == nil || req.GetDeviceId() != "dev-1" || req.GetCertificateSerial() != "0a1b" {
		t.Fatalf("SetDeviceEnrolled request = %v, want dev-1 serial 0a1b", req)
	}
	if !strings.Contains(out, "0a1b") {
		t.Errorf("output does not show the serial:\n%s", out)
	}

	fake = &fakePXEClient{}
	_, err = run(t, fake, "set-enrolled", "dev-1")
	var target *ErrCertificateSerialRequired
	if !errors.As(err, &target) {
		t.Errorf("set-enrolled without serial: err = %v, want *ErrCertificateSerialRequired", err)
	}
	if fake.calls != 0 {
		t.Errorf("set-enrolled without serial: %d RPCs made, want none", fake.calls)
	}
}
