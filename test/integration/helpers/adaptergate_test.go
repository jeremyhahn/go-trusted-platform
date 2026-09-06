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

//go:build integration

package helpers

import (
	"errors"
	"strings"
	"testing"
)

type namedAdapter struct{ name string }

func (a namedAdapter) Name() string { return a.name }

func TestAdapterSetupFailureWrapsTheSetupError(t *testing.T) {
	dialErr := errors.New("dial udp 127.0.0.1:9444: connection refused")

	failure := AdapterSetupFailure("device", "QUIC", dialErr)
	if failure == nil {
		t.Fatal("a non-nil setup error must produce a failure")
	}
	if !errors.Is(failure, dialErr) {
		t.Errorf("failure must unwrap to the setup error, got %v", failure)
	}

	var setupErr *AdapterSetupError
	if !errors.As(failure, &setupErr) {
		t.Fatalf("failure must be an *AdapterSetupError, got %T", failure)
	}
	if setupErr.Suite != "device" || setupErr.Adapter != "QUIC" {
		t.Errorf("suite/adapter not carried: %+v", setupErr)
	}

	msg := failure.Error()
	for _, want := range []string{"device", "QUIC", "unreachable", "connection refused"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message must name %q so a reader can locate the transport; got: %s", want, msg)
		}
	}
	if strings.Contains(strings.ToLower(msg), "skip") && !strings.Contains(msg, "not a skip") {
		t.Errorf("message must not read as a skip: %s", msg)
	}
}

func TestAdapterSetupFailureIsNilWhenSetupSucceeded(t *testing.T) {
	if failure := AdapterSetupFailure("device", "REST", nil); failure != nil {
		t.Errorf("a nil setup error must produce no failure, got %v", failure)
	}
}

func TestAdapterGateVerifyFailsWhenNoTransportExecuted(t *testing.T) {
	gate := &AdapterGate{suite: "device", configured: []string{"REST", "gRPC", "QUIC"}}

	err := gate.Verify()
	if err == nil {
		t.Fatal("a suite that executed zero transports must fail")
	}

	var zero *ZeroAdaptersError
	if !errors.As(err, &zero) {
		t.Fatalf("expected *ZeroAdaptersError, got %T", err)
	}
	if zero.Suite != "device" {
		t.Errorf("suite not carried: %+v", zero)
	}
	for _, want := range []string{"device", "zero transports", "REST, gRPC, QUIC"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message must name %q; got: %s", want, err.Error())
		}
	}
}

func TestAdapterGateRequireSetupCountsASuccessfulSetup(t *testing.T) {
	gate := NewAdapterGate(t, "device", "REST")

	gate.RequireSetup(t, "REST", nil)

	if gate.Count() != 1 {
		t.Errorf("a successful setup must count as an executed transport, got %d", gate.Count())
	}
	if err := gate.Verify(); err != nil {
		t.Errorf("guard must pass after a successful setup, got %v", err)
	}
}

func TestAdapterGateCountsEveryTransportThatSetUp(t *testing.T) {
	gate := NewAdapterGate(t, "device", "REST", "gRPC")

	gate.RequireSetup(t, "REST", nil)
	gate.RequireSetup(t, "gRPC", nil)

	if gate.Count() != 2 {
		t.Errorf("expected two executed transports, got %d", gate.Count())
	}
}

func TestZeroAdaptersErrorReportsAnEmptyConfiguredList(t *testing.T) {
	err := (&ZeroAdaptersError{Suite: "sdn"}).Error()
	if !strings.Contains(err, "configured: none") {
		t.Errorf("an empty configured list must read as none; got: %s", err)
	}
}

func TestAdapterEndpointResolvesEveryTransportTheSuitesUse(t *testing.T) {
	for _, adapter := range []string{"REST", "gRPC", "QUIC", "MCP", "Unix", "CLI"} {
		endpoint := AdapterEndpoint(adapter)
		if endpoint == "" || endpoint == "unknown transport" {
			t.Errorf("%s must resolve to a real endpoint, got %q", adapter, endpoint)
		}
	}
}

func TestAdapterEndpointMarksAnUnknownTransport(t *testing.T) {
	if got := AdapterEndpoint("carrier-pigeon"); got != "unknown transport" {
		t.Errorf("an unrecognised transport must be marked, got %q", got)
	}
}

func TestAdapterNamesListsEveryAdapter(t *testing.T) {
	names := AdapterNames([]namedAdapter{{"REST"}, {"gRPC"}, {"Unix"}})

	if strings.Join(names, ",") != "REST,gRPC,Unix" {
		t.Errorf("adapter names must be listed in order, got %v", names)
	}
}

func TestAdapterNamesOnAnEmptySliceYieldsNoNames(t *testing.T) {
	if names := AdapterNames([]namedAdapter{}); len(names) != 0 {
		t.Errorf("an empty adapter slice must yield no names, got %v", names)
	}
}
