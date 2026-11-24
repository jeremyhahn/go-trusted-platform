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
