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
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Device attestation reporting (#226) as the suite drives it on every
// transport (#429). The daemon answers each verb in one of three states --
// a result, "reporting unavailable", or "never collected" -- and every
// adapter maps its transport's spelling of the last two onto the typed
// errors below, so the tests compare states rather than wire formats.

// reasonNotConfigured is the phrase every transport carries when the node
// runs no reporting service.
const reasonNotConfigured = "reporting service is not configured"

// DeviceReport is the transport-neutral subset of a device attestation
// report the suite asserts on. A verdict never travels without its
// freshness and age.
type DeviceReport struct {
	DeviceID          string `json:"device_id"`
	Verified          bool   `json:"verified"`
	Fresh             bool   `json:"fresh"`
	AgeSeconds        int64  `json:"age_seconds"`
	PCRBaselineSource string `json:"pcr_baseline_source"`
}

// DeviceReportsResult is the fleet read.
type DeviceReportsResult struct {
	Reports []DeviceReport `json:"reports"`
	Count   int            `json:"count"`
}

// DeviceReportOptions names the device a single-device verb acts on.
type DeviceReportOptions struct {
	DeviceID string
}

// RefreshDeviceReportResult is the collector's acceptance of a refresh. It
// carries no verdict: the caller reads the report for that.
type RefreshDeviceReportResult struct {
	DeviceID string `json:"device_id"`
	Enqueued bool   `json:"enqueued"`
	Note     string `json:"note"`
}

// ErrReportingUnavailable is a reporting verb the node refused because it
// runs no reporting service or its collector has stopped.
type ErrReportingUnavailable struct {
	Transport string
	Operation string
	Err       error
}

func (e ErrReportingUnavailable) Error() string {
	return fmt.Sprintf("%s %s: attestation reporting is unavailable on this node: %v", e.Transport, e.Operation, e.Err)
}

func (e ErrReportingUnavailable) Unwrap() error { return e.Err }

// ErrReportNotCollected is a device the collector has never reached. It is
// its own state, never a negative verdict.
type ErrReportNotCollected struct {
	Transport string
	DeviceID  string
	Err       error
}

func (e ErrReportNotCollected) Error() string {
	return fmt.Sprintf("%s: device %s has never been collected: %v", e.Transport, e.DeviceID, e.Err)
}

func (e ErrReportNotCollected) Unwrap() error { return e.Err }

// classifyReportingText maps a failure whose only signal is its text (the
// CLI) onto the typed reporting errors. neverCollected is the transport's
// phrase for a device with no report; it is only consulted when deviceID is
// set. Any other failure is returned unchanged.
func classifyReportingText(transport, operation, deviceID, neverCollected string, err error) error {
	if isNotConfiguredText(err) {
		return ErrReportingUnavailable{Transport: transport, Operation: operation, Err: err}
	}
	if deviceID != "" && strings.Contains(err.Error(), neverCollected) {
		return ErrReportNotCollected{Transport: transport, DeviceID: deviceID, Err: err}
	}
	return err
}

// isNotConfiguredText reports whether err is the daemon's refusal on a node
// without a reporting service, which MCP and the CLI carry only as text.
func isNotConfiguredText(err error) bool {
	return strings.Contains(err.Error(), reasonNotConfigured)
}

// reportingRPC runs the reporting RPCs over an AttestationService client.
// The gRPC and Unix adapters differ only in the connection and in the error
// type an unclassified failure is wrapped in.
type reportingRPC struct {
	client    platformv1.AttestationServiceClient
	transport string
	wrap      func(method string, err error) error
}

// classify maps the reporting status codes onto the typed reporting errors.
// deviceID is set only for the single-device read, the one RPC whose
// NotFound means "never collected".
func (r reportingRPC) classify(method, deviceID string, err error) error {
	switch status.Code(err) {
	case codes.FailedPrecondition, codes.Unavailable:
		return ErrReportingUnavailable{Transport: r.transport, Operation: method, Err: err}
	case codes.NotFound:
		if deviceID != "" {
			return ErrReportNotCollected{Transport: r.transport, DeviceID: deviceID, Err: err}
		}
	}
	return r.wrap(method, err)
}

func (r reportingRPC) list(ctx context.Context) (*DeviceReportsResult, error) {
	resp, err := r.client.ListDeviceReports(ctx, &platformv1.ListDeviceReportsRequest{})
	if err != nil {
		return nil, r.classify("ListDeviceReports", "", err)
	}
	result := &DeviceReportsResult{Count: int(resp.GetTotal())}
	for _, report := range resp.GetReports() {
		result.Reports = append(result.Reports, reportFromProto(report))
	}
	return result, nil
}

func (r reportingRPC) get(ctx context.Context, opts DeviceReportOptions) (*DeviceReport, error) {
	resp, err := r.client.GetDeviceReport(ctx, &platformv1.GetDeviceReportRequest{DeviceId: opts.DeviceID})
	if err != nil {
		return nil, r.classify("GetDeviceReport", opts.DeviceID, err)
	}
	report := reportFromProto(resp.GetReport())
	return &report, nil
}

func (r reportingRPC) refresh(ctx context.Context, opts DeviceReportOptions) (*RefreshDeviceReportResult, error) {
	resp, err := r.client.RefreshDeviceReport(ctx, &platformv1.RefreshDeviceReportRequest{DeviceId: opts.DeviceID})
	if err != nil {
		return nil, r.classify("RefreshDeviceReport", "", err)
	}
	return &RefreshDeviceReportResult{
		DeviceID: resp.GetDeviceId(),
		Enqueued: resp.GetEnqueued(),
		Note:     resp.GetNote(),
	}, nil
}

func (r reportingRPC) callers(ctx context.Context) (*calleradmission.Description, error) {
	resp, err := r.client.DescribeCallerPolicy(ctx, &platformv1.DescribeCallerPolicyRequest{})
	if err != nil {
		return nil, r.wrap("DescribeCallerPolicy", err)
	}
	policy := resp.GetPolicy()
	return &calleradmission.Description{
		Strategy:               calleradmission.Strategy(policy.GetStrategy()),
		Identities:             policy.GetIdentities(),
		IdentitiesSource:       policy.GetIdentitiesSource(),
		ListValid:              policy.GetListValid(),
		InvalidEntries:         policy.GetInvalidEntries(),
		AnchorsConfigured:      policy.GetAnchorsConfigured(),
		AnchorSource:           policy.GetAnchorSource(),
		AttestedPeersAvailable: policy.GetAttestedPeersAvailable(),
		AdmitsNobody:           policy.GetAdmitsNobody(),
	}, nil
}

func reportFromProto(report *platformv1.DeviceAttestationReport) DeviceReport {
	return DeviceReport{
		DeviceID:          report.GetDeviceId(),
		Verified:          report.GetVerified(),
		Fresh:             report.GetFresh(),
		AgeSeconds:        report.GetAgeSeconds(),
		PCRBaselineSource: report.GetPcrBaselineSource(),
	}
}
