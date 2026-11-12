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
package rest

import (
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Device attestation reports (#226, #429). The webservice serves the
// reporting cache's own JSON — reporting.View for a report,
// calleradmission.Description for the policy — not the pb response
// wrappers, so each read has a decoder that places the payload on its
// reply. The refresh answers RefreshResponse, whose field names match the
// pb reply exactly, and decodes generically.
func init() {
	templatedRouteTable[platformv1.AttestationService_GetDeviceReport_FullMethodName] =
		itemRoute("/api/v1/attestation/reports/{device_id}", http.MethodGet, "{device_id}", "device_id")
	templatedRouteTable[platformv1.AttestationService_RefreshDeviceReport_FullMethodName] =
		itemRoute("/api/v1/attestation/reports/{device_id}/refresh", http.MethodPost, "{device_id}", "device_id")

	grpcMethodToRESTMap[platformv1.AttestationService_ListDeviceReports_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/attestation/reports", http.MethodGet}
	grpcMethodToRESTMap[platformv1.AttestationService_DescribeCallerPolicy_FullMethodName] = struct {
		path   string
		method string
	}{"/api/v1/attestation/callers", http.MethodGet}

	// Device verdicts are polled from a cursor; the webservice answers the
	// pb reply as protojson, which decodes generically. StreamDeviceVerdicts
	// is served over this route by NewStream.
	templatedRouteTable[platformv1.AttestationService_PollDeviceVerdicts_FullMethodName] = templatedRoute{
		path:   "/api/v1/attestation/verdicts",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "cursor", field: "cursor"},
			{name: "wait_ms", field: "wait_ms"},
		},
	}

	// Host manifests (#1686): the server answers the pb replies as
	// protojson, which decodes generically.
	templatedRouteTable[platformv1.AttestationService_ListManifests_FullMethodName] = templatedRoute{
		path:   "/api/v1/attestation/manifests",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "host_id", field: "host_id"},
			{name: "limit", field: "limit"},
			{name: "offset", field: "offset"},
		},
	}
	templatedRouteTable[platformv1.AttestationService_GetManifest_FullMethodName] =
		itemRoute("/api/v1/attestation/manifests/{id}", http.MethodGet, "{id}", "id")
	templatedRouteTable[platformv1.AttestationService_DeleteManifest_FullMethodName] =
		itemRoute("/api/v1/attestation/manifests/{id}", http.MethodDelete, "{id}", "id")

	restResponseDecoders[platformv1.AttestationService_GetDeviceReport_FullMethodName] = decodeDeviceReport
	restResponseDecoders[platformv1.AttestationService_ListDeviceReports_FullMethodName] = decodeDeviceReports
	restResponseDecoders[platformv1.AttestationService_DescribeCallerPolicy_FullMethodName] = decodeCallerPolicy
}

// reportJSON decodes the reporting cache's JSON (snake_case names, RFC 3339
// timestamps) into a pb message. protojson accepts proto field names and
// RFC 3339 for google.protobuf.Timestamp; unknown fields such as the list's
// count are discarded.
var reportJSON = protojson.UnmarshalOptions{DiscardUnknown: true}

// decodeDeviceReport places a bare reporting.View on GetDeviceReportResponse.
func decodeDeviceReport(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetDeviceReportResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.AttestationService_GetDeviceReport_FullMethodName}
	}
	report := &platformv1.DeviceAttestationReport{}
	if err := reportJSON.Unmarshal(raw, report); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Report = report
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeDeviceReports decodes the {"reports": [...], "count": n} list payload.
func decodeDeviceReports(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListDeviceReportsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.AttestationService_ListDeviceReports_FullMethodName}
	}
	if err := reportJSON.Unmarshal(raw, out); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Total = int32(len(out.Reports))
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeCallerPolicy places a bare calleradmission.Description on
// DescribeCallerPolicyResponse.
func decodeCallerPolicy(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.DescribeCallerPolicyResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.AttestationService_DescribeCallerPolicy_FullMethodName}
	}
	policy := &platformv1.CallerPolicyDescription{}
	if err := reportJSON.Unmarshal(raw, policy); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Policy = policy
	out.Status = &platformv1.Status{Success: true}
	return nil
}
