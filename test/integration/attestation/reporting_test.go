//go:build integration

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

package attestation

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// unknownDeviceID is a well-formed device id no collector has reached.
const unknownDeviceID = "999999999"

// testReporting exercises the device attestation report verbs (#226, #429)
// on one transport. The daemon either runs the reporting service or does
// not; every verb must say which in the same typed form on every
// transport, and "never collected" must never surface as a verdict.
func testReporting(t *testing.T, ctx context.Context, adapter AttestationCommands) {
	if _, isQUIC := adapter.(*QUICAdapter); isQUIC {
		requireNoQUICReportingSurface(t, ctx, adapter)
		return
	}

	t.Run("Callers", func(t *testing.T) {
		policy, err := adapter.DescribeCallerPolicy(ctx)
		if err != nil {
			t.Fatalf("DescribeCallerPolicy failed: %v", err)
		}
		requirePolicyFailsClosed(t, policy)
	})

	list, err := adapter.ListDeviceReports(ctx)
	var unavailable ErrReportingUnavailable
	if errors.As(err, &unavailable) {
		t.Run("Unavailable", func(t *testing.T) {
			requireReportingUnavailable(t, ctx, adapter)
		})
		return
	}
	if err != nil {
		t.Fatalf("ListDeviceReports failed: %v", err)
	}
	t.Run("Served", func(t *testing.T) {
		requireReportingServed(t, ctx, adapter, list)
	})
}

// requirePolicyFailsClosed asserts the description never reads as open
// when the policy cannot admit anyone.
func requirePolicyFailsClosed(t *testing.T, policy *calleradmission.Description) {
	t.Helper()
	if policy.Strategy == "" && !policy.AdmitsNobody {
		t.Errorf("no compiled policy must admit nobody: %+v", policy)
	}
	if !policy.AnchorsConfigured && !policy.AdmitsNobody {
		t.Errorf("a policy without trust anchors must admit nobody: %+v", policy)
	}
	if !policy.ListValid && !policy.AdmitsNobody {
		t.Errorf("a policy with an unparseable identity list must admit nobody: %+v", policy)
	}
}

// requireReportingUnavailable asserts the single-device verbs agree with
// the fleet read on a node without a reporting service. The read in
// particular must not turn into "never collected".
func requireReportingUnavailable(t *testing.T, ctx context.Context, adapter AttestationCommands) {
	t.Helper()
	opts := DeviceReportOptions{DeviceID: unknownDeviceID}
	var unavailable ErrReportingUnavailable

	if _, err := adapter.GetDeviceReport(ctx, opts); !errors.As(err, &unavailable) {
		t.Errorf("GetDeviceReport: got %v, want ErrReportingUnavailable", err)
	}
	if _, err := adapter.RefreshDeviceReport(ctx, opts); !errors.As(err, &unavailable) {
		t.Errorf("RefreshDeviceReport: got %v, want ErrReportingUnavailable", err)
	}
}

// requireReportingServed asserts the verbs on a node that runs the
// reporting service.
func requireReportingServed(t *testing.T, ctx context.Context, adapter AttestationCommands, list *DeviceReportsResult) {
	t.Helper()
	if list.Count != len(list.Reports) {
		t.Errorf("ListDeviceReports: count %d, %d reports", list.Count, len(list.Reports))
	}
	for _, report := range list.Reports {
		if report.DeviceID == "" || report.AgeSeconds < 0 {
			t.Errorf("ListDeviceReports: report without identity or age: %+v", report)
		}
	}

	opts := DeviceReportOptions{DeviceID: unknownDeviceID}
	var notCollected ErrReportNotCollected
	if _, err := adapter.GetDeviceReport(ctx, opts); !errors.As(err, &notCollected) {
		t.Errorf("GetDeviceReport(%s): got %v, want ErrReportNotCollected", unknownDeviceID, err)
	}

	refresh, err := adapter.RefreshDeviceReport(ctx, opts)
	if err != nil {
		t.Fatalf("RefreshDeviceReport failed: %v", err)
	}
	if refresh.DeviceID != unknownDeviceID || !refresh.Enqueued || refresh.Note == "" {
		t.Errorf("RefreshDeviceReport: want the device echoed, enqueued and a note, got %+v", refresh)
	}
}

// requireNoQUICReportingSurface asserts QUIC declares the #386 gap for every
// reporting verb rather than timing out or answering.
func requireNoQUICReportingSurface(t *testing.T, ctx context.Context, adapter AttestationCommands) {
	t.Helper()
	opts := DeviceReportOptions{DeviceID: unknownDeviceID}
	calls := map[string]func() error{
		"ListDeviceReports":    func() error { _, err := adapter.ListDeviceReports(ctx); return err },
		"GetDeviceReport":      func() error { _, err := adapter.GetDeviceReport(ctx, opts); return err },
		"RefreshDeviceReport":  func() error { _, err := adapter.RefreshDeviceReport(ctx, opts); return err },
		"DescribeCallerPolicy": func() error { _, err := adapter.DescribeCallerPolicy(ctx); return err },
	}
	for name, call := range calls {
		var noSurface surface.ErrNoSurface
		if err := call(); !errors.As(err, &noSurface) {
			t.Errorf("%s over QUIC: got %v, want surface.ErrNoSurface (#386)", name, err)
		}
	}
}

// TestAttestationReporting_TransportsAgree asserts every transport with a
// reporting surface describes the same caller policy and the same
// reporting state: the CLI renders the gRPC message, REST and MCP marshal
// the policy directly, and any drift between them is a parity bug.
func TestAttestationReporting_TransportsAgree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapters := []AttestationCommands{
		NewUnixAdapter(),
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewMCPAdapter(),
	}
	gate := helpers.NewAdapterGate(t, "attestation-reporting", helpers.AdapterNames(adapters)...)

	var (
		reference       *calleradmission.Description
		referenceName   string
		referenceServed bool
	)
	for _, adapter := range adapters {
		gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
		policy, policyErr := adapter.DescribeCallerPolicy(ctx)
		_, listErr := adapter.ListDeviceReports(ctx)
		if err := adapter.Teardown(ctx); err != nil {
			t.Errorf("%s teardown failed: %v", adapter.Name(), err)
		}
		if policyErr != nil {
			t.Fatalf("%s DescribeCallerPolicy failed: %v", adapter.Name(), policyErr)
		}
		var unavailable ErrReportingUnavailable
		if listErr != nil && !errors.As(listErr, &unavailable) {
			t.Fatalf("%s ListDeviceReports failed: %v", adapter.Name(), listErr)
		}
		served := listErr == nil

		if reference == nil {
			reference, referenceName, referenceServed = policy, adapter.Name(), served
			continue
		}
		if !reflect.DeepEqual(normalisePolicy(policy), normalisePolicy(reference)) {
			t.Errorf("caller policy differs: %s %+v, %s %+v", adapter.Name(), policy, referenceName, reference)
		}
		if served != referenceServed {
			t.Errorf("reporting state differs: %s served=%t, %s served=%t", adapter.Name(), served, referenceName, referenceServed)
		}
	}
}

// normalisePolicy treats an empty list and an absent one as the same: JSON
// transports omit what protobuf renders as an empty slice.
func normalisePolicy(policy *calleradmission.Description) calleradmission.Description {
	normalised := *policy
	if len(normalised.Identities) == 0 {
		normalised.Identities = nil
	}
	if len(normalised.InvalidEntries) == 0 {
		normalised.InvalidEntries = nil
	}
	return normalised
}

func TestClassifyReportingText(t *testing.T) {
	notConfigured := errors.New("ATTESTATION_REPORTING_NOT_CONFIGURED: the attestation reporting service is not configured on this node")
	neverCollected := errors.New("platformctl: device 7 has never been collected")
	other := errors.New("connection refused")

	t.Run("NotConfigured", func(t *testing.T) {
		err := classifyReportingText("CLI", "GetDeviceReport", "7", cliNeverCollected, notConfigured)
		var unavailable ErrReportingUnavailable
		if !errors.As(err, &unavailable) || !errors.Is(err, notConfigured) {
			t.Fatalf("got %v, want ErrReportingUnavailable wrapping the cause", err)
		}
	})
	t.Run("NeverCollected", func(t *testing.T) {
		err := classifyReportingText("CLI", "GetDeviceReport", "7", cliNeverCollected, neverCollected)
		var notCollected ErrReportNotCollected
		if !errors.As(err, &notCollected) || notCollected.DeviceID != "7" {
			t.Fatalf("got %v, want ErrReportNotCollected for device 7", err)
		}
	})
	t.Run("NeverCollectedPhraseWithoutDevice", func(t *testing.T) {
		// Only the single-device read passes a device; elsewhere the
		// phrase is not a state the suite classifies.
		if err := classifyReportingText("CLI", "ListDeviceReports", "", cliNeverCollected, neverCollected); err != neverCollected {
			t.Fatalf("got %v, want the cause unchanged", err)
		}
	})
	t.Run("Unrelated", func(t *testing.T) {
		if err := classifyReportingText("CLI", "GetDeviceReport", "7", cliNeverCollected, other); err != other {
			t.Fatalf("got %v, want the cause unchanged", err)
		}
	})
}

// TestClassifyMCPReportingError pins the MCP adapter to the JSON-RPC code:
// never collected is NotFound (-32005) on the single-device read, whatever
// the message says.
func TestClassifyMCPReportingError(t *testing.T) {
	notFound := &MCPAdapterError{Operation: "tools/call", Code: mcpwire.NotFound, Message: "device 7"}
	notConfigured := &MCPAdapterError{Operation: "tools/call", Code: mcpwire.InternalError,
		Message: "ATTESTATION_REPORTING_NOT_CONFIGURED: the attestation reporting service is not configured on this node"}
	textOnly := &MCPAdapterError{Operation: "tools/call", Code: mcpwire.InternalError,
		Message: "attestation: no report has been collected for device 7"}

	t.Run("NotFoundForDevice", func(t *testing.T) {
		err := classifyMCPReportingError("MCP", "GetDeviceReport", "7", notFound)
		var notCollected ErrReportNotCollected
		if !errors.As(err, &notCollected) || notCollected.DeviceID != "7" || !errors.Is(err, notFound) {
			t.Fatalf("got %v, want ErrReportNotCollected for device 7 wrapping the cause", err)
		}
	})
	t.Run("NotConfigured", func(t *testing.T) {
		err := classifyMCPReportingError("MCP", "GetDeviceReport", "7", notConfigured)
		var unavailable ErrReportingUnavailable
		if !errors.As(err, &unavailable) {
			t.Fatalf("got %v, want ErrReportingUnavailable", err)
		}
	})
	t.Run("NotFoundWithoutDevice", func(t *testing.T) {
		if err := classifyMCPReportingError("MCP", "ListDeviceReports", "", notFound); err != notFound {
			t.Fatalf("got %v, want the cause unchanged", err)
		}
	})
	t.Run("PhraseWithoutCode", func(t *testing.T) {
		// The text alone no longer classifies: only the code does.
		if err := classifyMCPReportingError("MCP", "GetDeviceReport", "7", textOnly); err != textOnly {
			t.Fatalf("got %v, want the cause unchanged", err)
		}
	})
}

func TestReportingRPCClassify(t *testing.T) {
	wrapped := errors.New("wrapped")
	rpc := reportingRPC{
		transport: "gRPC",
		wrap:      func(string, error) error { return wrapped },
	}

	tests := []struct {
		name     string
		code     codes.Code
		deviceID string
		check    func(error) bool
	}{
		{"FailedPrecondition", codes.FailedPrecondition, "7", func(err error) bool {
			var target ErrReportingUnavailable
			return errors.As(err, &target)
		}},
		{"CollectorStopped", codes.Unavailable, "", func(err error) bool {
			var target ErrReportingUnavailable
			return errors.As(err, &target)
		}},
		{"NotFoundForDevice", codes.NotFound, "7", func(err error) bool {
			var target ErrReportNotCollected
			return errors.As(err, &target) && target.DeviceID == "7"
		}},
		{"NotFoundWithoutDevice", codes.NotFound, "", func(err error) bool { return err == wrapped }},
		{"PermissionDenied", codes.PermissionDenied, "7", func(err error) bool { return err == wrapped }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rpc.classify("GetDeviceReport", tt.deviceID, status.Error(tt.code, "reason"))
			if !tt.check(err) {
				t.Fatalf("classify(%s): unexpected %v", tt.code, err)
			}
		})
	}
}
