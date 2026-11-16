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

package rest

// BMC web certificate replacement and the enrol and restore ceremonies over
// REST.
//
// The daemon serves these under /api/v1/bmc/{profileID}
// (pkg/api/daemon/rest_service.go; handlers in pkg/webservice/v1/bmc). The
// wire differs from the pb messages in two ways:
//
//   - PEM travels as text. The pb fields are bytes, which protojson and
//     encoding/json would send and expect base64-encoded.
//   - The ceremony replies carry device_id as a decimal string and the
//     certificate times as RFC 3339 strings.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errBMCCertPEMRequired is returned when a web certificate replacement lacks
// the certificate or the key PEM.
var errBMCCertPEMRequired = errors.New("bmc: cert_pem and key_pem are required")

// bmcCertMetaWire mirrors the daemon's FactoryCertMetaResponse.
type bmcCertMetaWire struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SPKISHA256   string    `json:"spki_sha256"`
	SHA256       string    `json:"sha256"`
	CapturedAt   time.Time `json:"captured_at"`
}

// bmcStepWire mirrors the daemon's EnrollStepResponse.
type bmcStepWire struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// bmcEnrollWire mirrors the daemon's EnrollResponse.
type bmcEnrollWire struct {
	DeviceID        uint64          `json:"device_id,string"`
	Endpoint        string          `json:"endpoint"`
	Hostname        string          `json:"hostname"`
	DNSName         string          `json:"dns_name"`
	PinSPKISHA256   string          `json:"pin_spki_sha256"`
	FactoryCertPEM  string          `json:"factory_cert_pem"`
	FactoryCertMeta bmcCertMetaWire `json:"factory_cert_meta"`
	NewCertPEM      string          `json:"new_cert_pem"`
	CACertPEM       string          `json:"ca_cert_pem"`
	Steps           []bmcStepWire   `json:"steps"`
}

// bmcRestoreWire mirrors the daemon's RestoreResponse.
type bmcRestoreWire struct {
	DeviceID    uint64          `json:"device_id,string"`
	Endpoint    string          `json:"endpoint"`
	Hostname    string          `json:"hostname"`
	NewCertMeta bmcCertMetaWire `json:"new_cert_meta"`
	NewCertPEM  string          `json:"new_cert_pem"`
	Steps       []bmcStepWire   `json:"steps"`
}

// bmcTimestamp converts a wire time; the zero time stays unset.
func bmcTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// bmcPEM converts PEM text to the pb bytes field; empty stays nil.
func bmcPEM(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

// toProto builds the pb certificate metadata from its wire form.
func (m bmcCertMetaWire) toProto() *platformv1.BMCFactoryCertMeta {
	return &platformv1.BMCFactoryCertMeta{
		Subject:      m.Subject,
		Issuer:       m.Issuer,
		SerialNumber: m.SerialNumber,
		NotBefore:    bmcTimestamp(m.NotBefore),
		NotAfter:     bmcTimestamp(m.NotAfter),
		SpkiSha256:   m.SPKISHA256,
		Sha256:       m.SHA256,
		CapturedAt:   bmcTimestamp(m.CapturedAt),
	}
}

func bmcStepsToProto(steps []bmcStepWire) []*platformv1.BMCEnrollStep {
	if len(steps) == 0 {
		return nil
	}
	out := make([]*platformv1.BMCEnrollStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, &platformv1.BMCEnrollStep{Name: s.Name, Ok: s.OK, Detail: s.Detail})
	}
	return out
}

func decodeBMCReplaceWebCertificate(raw []byte) (*platformv1.BMCReplaceWebCertificateResponse, error) {
	var wire struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("bmc: decode replace-certificate reply: %w", err)
	}
	return &platformv1.BMCReplaceWebCertificateResponse{Message: wire.Status}, nil
}

func decodeBMCEnroll(raw []byte) (*platformv1.BMCEnrollResponse, error) {
	var wire bmcEnrollWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("bmc: decode enroll reply: %w", err)
	}
	return &platformv1.BMCEnrollResponse{
		DeviceId:        wire.DeviceID,
		Endpoint:        wire.Endpoint,
		Hostname:        wire.Hostname,
		DnsName:         wire.DNSName,
		PinSpkiSha256:   wire.PinSPKISHA256,
		FactoryCertPem:  bmcPEM(wire.FactoryCertPEM),
		FactoryCertMeta: wire.FactoryCertMeta.toProto(),
		NewCertPem:      bmcPEM(wire.NewCertPEM),
		CaCertPem:       bmcPEM(wire.CACertPEM),
		Steps:           bmcStepsToProto(wire.Steps),
	}, nil
}

func decodeBMCRestore(raw []byte) (*platformv1.BMCRestoreResponse, error) {
	var wire bmcRestoreWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("bmc: decode restore reply: %w", err)
	}
	return &platformv1.BMCRestoreResponse{
		DeviceId:    wire.DeviceID,
		Endpoint:    wire.Endpoint,
		Hostname:    wire.Hostname,
		NewCertMeta: wire.NewCertMeta.toProto(),
		NewCertPem:  bmcPEM(wire.NewCertPEM),
		Steps:       bmcStepsToProto(wire.Steps),
	}, nil
}

func init() {
	replaceCert := platformv1.BMCService_ReplaceWebCertificate_FullMethodName
	enroll := platformv1.BMCService_EnrollBMC_FullMethodName
	restore := platformv1.BMCService_RestoreFactoryCert_FullMethodName

	templatedRouteTable[replaceCert] = bmcRoute("/api/v1/bmc/{profileID}/cert", http.MethodPut)
	templatedRouteTable[enroll] = bmcRoute("/api/v1/bmc/{profileID}/enroll", http.MethodPost)
	templatedRouteTable[restore] = bmcRoute("/api/v1/bmc/{profileID}/cert/restore", http.MethodPost)

	// EnrollBMC sends its optional bools under the pb names, which the
	// daemon reads as is; only the certificate replacement needs an encoder.
	restRequestEncoders[replaceCert] = requestEncoder(replaceCert,
		func(r *platformv1.BMCReplaceWebCertificateRequest) (map[string]interface{}, error) {
			if len(r.GetCertPem()) == 0 || len(r.GetKeyPem()) == 0 {
				return nil, errBMCCertPEMRequired
			}
			return map[string]interface{}{
				"cert_pem": string(r.GetCertPem()),
				"key_pem":  string(r.GetKeyPem()),
			}, nil
		})

	restResponseDecoders[replaceCert] = wireDecoder(replaceCert, decodeBMCReplaceWebCertificate)
	restResponseDecoders[enroll] = wireDecoder(enroll, decodeBMCEnroll)
	restResponseDecoders[restore] = wireDecoder(restore, decodeBMCRestore)
}
