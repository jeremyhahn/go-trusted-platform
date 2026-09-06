// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package mcp

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Device attestation reports (#226, #429). The server tools return the
// reporting cache's own JSON shapes — reporting.View, {reports, count},
// calleradmission.Description — with snake_case names and RFC 3339
// timestamps. The generic encoding/json round-trip cannot place an RFC 3339
// string on a google.protobuf.Timestamp, so every reply goes through
// protojson here. Server tools: pkg/api/mcp/attestation_report_tools.go.
func init() {
	for method, tool := range map[string]string{
		platformv1.AttestationService_GetDeviceReport_FullMethodName:      "attestation_device_report",
		platformv1.AttestationService_ListDeviceReports_FullMethodName:    "attestation_device_reports",
		platformv1.AttestationService_RefreshDeviceReport_FullMethodName:  "attestation_device_refresh",
		platformv1.AttestationService_DescribeCallerPolicy_FullMethodName: "attestation_caller_policy",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}
	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.AttestationService_GetDeviceReport_FullMethodName:      decodeDeviceReportResult,
		platformv1.AttestationService_ListDeviceReports_FullMethodName:    decodeDeviceReportsResult,
		platformv1.AttestationService_RefreshDeviceReport_FullMethodName:  decodeDeviceRefreshResult,
		platformv1.AttestationService_DescribeCallerPolicy_FullMethodName: decodeCallerPolicyResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// reportJSON decodes the reporting cache's JSON into a pb message; unknown
// fields such as the list's count are discarded.
var reportJSON = protojson.UnmarshalOptions{DiscardUnknown: true}

// decodeReportJSON renders a generic tool result back to JSON and decodes it
// with protojson into msg.
func decodeReportJSON(result interface{}, msg proto.Message) error {
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	if err := reportJSON.Unmarshal(data, msg); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	return nil
}

// decodeDeviceReportResult places a bare reporting.View on the reply.
func decodeDeviceReportResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetDeviceReportResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.AttestationService_GetDeviceReport_FullMethodName}
	}
	report := &platformv1.DeviceAttestationReport{}
	if err := decodeReportJSON(result, report); err != nil {
		return err
	}
	out.Report = report
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeDeviceReportsResult decodes {"reports": [...], "count": n}.
func decodeDeviceReportsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListDeviceReportsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.AttestationService_ListDeviceReports_FullMethodName}
	}
	if err := decodeReportJSON(result, out); err != nil {
		return err
	}
	out.Total = int32(len(out.Reports))
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeDeviceRefreshResult decodes {"device_id", "enqueued", "note"}.
func decodeDeviceRefreshResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.RefreshDeviceReportResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.AttestationService_RefreshDeviceReport_FullMethodName}
	}
	if err := decodeReportJSON(result, out); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeCallerPolicyResult places a bare calleradmission.Description on the
// reply.
func decodeCallerPolicyResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DescribeCallerPolicyResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.AttestationService_DescribeCallerPolicy_FullMethodName}
	}
	policy := &platformv1.CallerPolicyDescription{}
	if err := decodeReportJSON(result, policy); err != nil {
		return err
	}
	out.Policy = policy
	out.Status = &platformv1.Status{Success: true}
	return nil
}
