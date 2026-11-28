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

package switchmgmt

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// requireNameRefusal checks that NewService returned no service and an
// ErrInvalidConfig on the name field.
func requireNameRefusal(t *testing.T, svc *Service, err error) ErrInvalidConfig {
	t.Helper()
	if svc != nil {
		svc.Close()
		t.Fatalf("NewService returned a service, want nil")
	}
	var cfgErr ErrInvalidConfig
	if !errors.As(err, &cfgErr) {
		t.Fatalf("NewService error = %v, want ErrInvalidConfig", err)
	}
	if cfgErr.Field != "name" {
		t.Fatalf("ErrInvalidConfig.Field = %q, want name", cfgErr.Field)
	}
	return cfgErr
}

func TestNewService_RefusesDuplicateName(t *testing.T) {
	svc, err := NewService([]Config{
		{Name: "core-1", Vendor: VendorNoop, Host: "192.0.2.10"},
		{Name: "core-1", Vendor: VendorNoop, Host: "192.0.2.11"},
	}, slog.New(slog.DiscardHandler))
	requireNameRefusal(t, svc, err)
	if !strings.Contains(err.Error(), "core-1") {
		t.Errorf("error %q does not name core-1", err)
	}
}

func TestNewService_RefusesDuplicateHostFallback(t *testing.T) {
	svc, err := NewService([]Config{
		{Vendor: VendorNoop, Host: "192.0.2.10"},
		{Vendor: VendorNoop, Host: "192.0.2.10"},
	}, slog.New(slog.DiscardHandler))
	requireNameRefusal(t, svc, err)
	if !strings.Contains(err.Error(), "192.0.2.10") {
		t.Errorf("error %q does not name 192.0.2.10", err)
	}
}

func TestNewService_RefusesNameThatEqualsAnotherHost(t *testing.T) {
	svc, err := NewService([]Config{
		{Name: "192.0.2.10", Vendor: VendorNoop},
		{Vendor: VendorNoop, Host: "192.0.2.10"},
	}, slog.New(slog.DiscardHandler))
	requireNameRefusal(t, svc, err)
}

func TestNewService_RefusesEmptyIdentity(t *testing.T) {
	svc, err := NewService([]Config{
		{Vendor: VendorNoop},
	}, slog.New(slog.DiscardHandler))
	requireNameRefusal(t, svc, err)
}

func TestNewService_IdentityCheckedBeforeAnyManager(t *testing.T) {
	svc, err := NewService([]Config{
		{Name: "core-1", Vendor: VendorNoop},
		{Name: "core-1", Vendor: VendorNoop},
		{Name: "edge-9", Vendor: "unknown-vendor"},
	}, slog.New(slog.DiscardHandler))
	var unsupported ErrUnsupportedVendor
	if errors.As(err, &unsupported) {
		t.Fatalf("NewService error = %v, want the identity refusal before NewManager", err)
	}
	requireNameRefusal(t, svc, err)
}

func TestNewService_DistinctIdentitiesBuild(t *testing.T) {
	svc, err := NewService([]Config{
		{Name: "core-1", Vendor: VendorNoop, Host: "192.0.2.10"},
		{Name: "core-2", Vendor: VendorNoop, Host: "192.0.2.10"},
		{Vendor: VendorNoop, Host: "192.0.2.11"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewService error = %v, want nil", err)
	}
	defer svc.Close()
	for _, name := range []string{"core-1", "core-2", "192.0.2.11"} {
		if _, err := svc.Manager(name); err != nil {
			t.Errorf("Manager(%q) error = %v, want nil", name, err)
		}
	}
}

// aliasStatusHeader has a 16-wide Port column so port-channel10 fits.
const aliasStatusHeader = "Port            Name               Status       Vlan       Duplex  Speed   Type\n"

func aliasStatusRow(port, state string) string {
	return padRight(port, 16) + padRight("--", 19) + padRight(state, 13) + "100        auto    auto    10/100/1000\n"
}

func aliasMock(request, row string) *mockSSHExecutor {
	mock := newMockSSHExecutor()
	mock.outputs["show interfaces "+request+" switchport"] = concurrencySwitchportOutput
	mock.outputs["show interfaces "+request+" status"] = aliasStatusHeader + aliasStatusRow(row, "connected")
	return mock
}

func TestSSHManager_GetPortStatus_MatchesInterfaceAliases(t *testing.T) {
	cases := []struct{ request, row string }{
		{"Ethernet1/3", "Eth1/3"},
		{"Eth1/3", "Ethernet1/3"},
		{"ethernet1/3", "Eth1/3"},
		{"port-channel10", "Po10"},
		{"Po10", "port-channel10"},
		{"Port-Channel10", "po10"},
	}
	for _, tc := range cases {
		t.Run(tc.request+"_"+tc.row, func(t *testing.T) {
			m := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), aliasMock(tc.request, tc.row))
			status, err := m.GetPortStatus(context.Background(), tc.request)
			if err != nil {
				t.Fatalf("GetPortStatus(%q) with row %q error = %v, want nil", tc.request, tc.row, err)
			}
			if !status.Enabled || !status.LinkUp {
				t.Errorf("Enabled=%v LinkUp=%v, want both true", status.Enabled, status.LinkUp)
			}
			if status.AccessVLAN != 100 {
				t.Errorf("AccessVLAN = %d, want 100", status.AccessVLAN)
			}
			if status.Port != tc.request {
				t.Errorf("Port = %q, want %q", status.Port, tc.request)
			}
		})
	}
}

func TestSSHManager_GetPortStatus_AliasDoesNotMatchOtherPort(t *testing.T) {
	cases := []struct{ request, row string }{
		{"Ethernet1/3", "Eth1/30"},
		{"Eth10", "Po10"},
		{"port-channel10", "Po1"},
	}
	for _, tc := range cases {
		t.Run(tc.request+"_"+tc.row, func(t *testing.T) {
			m := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), aliasMock(tc.request, tc.row))
			_, err := m.GetPortStatus(context.Background(), tc.request)
			var parseErr ErrSSHParseOutputFailed
			if !errors.As(err, &parseErr) {
				t.Fatalf("GetPortStatus(%q) with row %q error = %v, want ErrSSHParseOutputFailed", tc.request, tc.row, err)
			}
			if want := "show interfaces " + tc.request + " status"; parseErr.Command != want {
				t.Errorf("Command = %q, want %q", parseErr.Command, want)
			}
		})
	}
}
