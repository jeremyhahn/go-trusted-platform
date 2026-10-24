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

package proxy

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// clientCommand is one subcommand that reaches the proxy client, with the
// message its WrappedError carries when the client call fails.
type clientCommand struct {
	name    string
	args    []string
	wantMsg string
}

var clientCommands = []clientCommand{
	{"route add", []string{"route", "add", "--id", "web", "--pool", "p", "--auth-mode", "public"}, "failed to create proxy route"},
	{"route get", []string{"route", "get", "web"}, "failed to get proxy route"},
	{"route update", []string{"route", "update", "--id", "web", "--pool", "p", "--auth-mode", "public"}, "failed to update proxy route"},
	{"route delete", []string{"route", "delete", "web"}, "failed to delete proxy route"},
	{"route list", []string{"route", "list"}, "failed to list proxy routes"},
	{"pool add", []string{"pool", "add", "--id", "p", "--backend", "https://b:8443"}, "failed to create proxy pool"},
	{"pool get", []string{"pool", "get", "p"}, "failed to get proxy pool"},
	{"pool update", []string{"pool", "update", "--id", "p", "--backend", "https://b:8443"}, "failed to update proxy pool"},
	{"pool delete", []string{"pool", "delete", "p"}, "failed to delete proxy pool"},
	{"pool list", []string{"pool", "list"}, "failed to list proxy pools"},
	{"status", []string{"status"}, "failed to get proxy status"},
	{"reload", []string{"reload"}, "failed to reload proxy config"},
	{"zone-matrix", []string{"zone-matrix"}, "failed to get proxy zone matrix"},
}

// withCountingFactory installs a client factory that hands out fake and
// counts how often the factory and the returned close function are called.
func withCountingFactory(t *testing.T, fake *fakeCLIClient, factoryErr error) (dials, closes *int) {
	t.Helper()
	origFactory := newProxyClient
	origOutput := output
	dials, closes = new(int), new(int)
	newProxyClient = func(flags *cli.CommonFlags) (proxyClient, func() error, error) {
		*dials++
		if factoryErr != nil {
			return nil, nil, factoryErr
		}
		return fake, func() error { *closes++; return nil }, nil
	}
	output = func(flags *cli.CommonFlags, v any) error { return nil }
	t.Cleanup(func() {
		newProxyClient = origFactory
		output = origOutput
	})
	return dials, closes
}

func TestClientCommands_ClientErrorIsWrapped(t *testing.T) {
	for _, tc := range clientCommands {
		t.Run(tc.name, func(t *testing.T) {
			withCountingFactory(t, &fakeCLIClient{err: errFakeClient}, nil)

			err := execute(t, tc.args...)
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) {
				t.Fatalf("err = %v, want *WrappedError", err)
			}
			if wrapped.Msg != tc.wantMsg {
				t.Errorf("Msg = %q, want %q", wrapped.Msg, tc.wantMsg)
			}
			if !errors.Is(err, errFakeClient) {
				t.Errorf("err = %v, does not wrap the client failure", err)
			}
			if want := tc.wantMsg + ": " + errFakeClient.Error(); err.Error() != want {
				t.Errorf("Error() = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestClientCommands_FactoryErrorReturnedUnwrapped(t *testing.T) {
	factoryErr := errors.New("connect failed")
	for _, tc := range clientCommands {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeCLIClient{}
			withCountingFactory(t, fake, factoryErr)

			// A nil close function must not be deferred on a failed dial.
			err := execute(t, tc.args...)
			if !errors.Is(err, factoryErr) {
				t.Fatalf("err = %v, want factory error", err)
			}
			var wrapped *WrappedError
			if errors.As(err, &wrapped) {
				t.Errorf("factory error wrapped as %q, want it returned as is", wrapped.Msg)
			}
			if fake.lastCall != "" {
				t.Errorf("client invoked (%s) after a failed dial", fake.lastCall)
			}
		})
	}
}

func TestClientCommands_CloseClientOnce(t *testing.T) {
	for _, tc := range clientCommands {
		t.Run(tc.name, func(t *testing.T) {
			dials, closes := withCountingFactory(t, &fakeCLIClient{}, nil)

			if err := execute(t, tc.args...); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if *dials != 1 || *closes != 1 {
				t.Errorf("dials = %d closes = %d, want 1 and 1", *dials, *closes)
			}
		})
	}
}

func TestUpdateCommands_InvalidFlagsRejectedBeforeDial(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{"route update without id", []string{"route", "update", "--pool", "p", "--auth-mode", "public"}, "--id is required"},
		{"route update without pool", []string{"route", "update", "--id", "web", "--auth-mode", "public"}, "--pool is required"},
		{"route update without auth mode", []string{"route", "update", "--id", "web", "--pool", "p"}, "--auth-mode is required (public, mtls, token, mtls-or-token)"},
		{"pool update without id", []string{"pool", "update", "--backend", "https://b:8443"}, "--id is required"},
		{"pool update without backend", []string{"pool", "update", "--id", "p"}, "at least one --backend is required"},
		// The string-slice flag parses an empty value as no backends at all.
		{"pool update with empty backend", []string{"pool", "update", "--id", "p", "--backend", ""}, "at least one --backend is required"},
		{"pool update with negative weight", []string{"pool", "update", "--id", "p", "--backend", "https://b:8443=-1"}, "backend weight must not be negative: https://b:8443=-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dials, _ := withCountingFactory(t, &fakeCLIClient{}, nil)

			err := execute(t, tc.args...)
			var msgErr *MessageError
			if !errors.As(err, &msgErr) {
				t.Fatalf("err = %v, want *MessageError", err)
			}
			if err.Error() != tc.wantMsg {
				t.Errorf("Error() = %q, want %q", err.Error(), tc.wantMsg)
			}
			if *dials != 0 {
				t.Errorf("client dialled %d time(s) for invalid flags", *dials)
			}
		})
	}
}
