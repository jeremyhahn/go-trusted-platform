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

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// PEM-shaped fixtures. The key fixture uses a neutral block type: the SDK
// passes the text through unchanged, so its type does not matter here.
const (
	bmcTestCertPEM = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n"
	bmcTestKeyPEM  = "-----BEGIN TEST BLOCK-----\nB\n-----END TEST BLOCK-----\n"
	bmcTestCAPEM   = "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n"
)

// certCapture records the one API request a test sends and answers it with
// the given status and body. The /health/live probe from Connect is ignored.
type certCapture struct {
	method string
	path   string
	body   map[string]interface{}
	hits   int
}

func (c *certCapture) handler(t *testing.T, code int, reply string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		c.hits++
		c.method = r.Method
		c.path = r.URL.Path
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		c.body = map[string]interface{}{}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &c.body); err != nil {
				t.Errorf("body is not JSON: %v (%q)", err, raw)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(reply))
	}
}

func TestBMCReplaceWebCertificate_SendsPEMText(t *testing.T) {
	var c certCapture
	a, _ := adapterAgainst(t, c.handler(t, http.StatusOK, `{"success":true,"payload":{"status":"ok"}}`))

	req := &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 42,
		CertPem:   []byte(bmcTestCertPEM),
		KeyPem:    []byte(bmcTestKeyPEM),
	}
	resp := &platformv1.BMCReplaceWebCertificateResponse{}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.BMCService_ReplaceWebCertificate_FullMethodName, req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if c.method != http.MethodPut || c.path != "/api/v1/bmc/42/cert" {
		t.Errorf("request = %s %s, want PUT /api/v1/bmc/42/cert", c.method, c.path)
	}
	if got := c.body["cert_pem"]; got != bmcTestCertPEM {
		t.Errorf("cert_pem = %q, want the PEM text", got)
	}
	if got := c.body["key_pem"]; got != bmcTestKeyPEM {
		t.Errorf("key_pem = %q, want the PEM text", got)
	}
	if _, has := c.body["profile_id"]; has {
		t.Errorf("body still contains profile_id: %v", c.body)
	}
	if resp.GetMessage() != "ok" {
		t.Errorf("Message = %q, want ok", resp.GetMessage())
	}
}

func TestBMCReplaceWebCertificate_EmptyPEMRefused(t *testing.T) {
	for name, req := range map[string]*platformv1.BMCReplaceWebCertificateRequest{
		"cert": {ProfileId: 42, KeyPem: []byte(bmcTestKeyPEM)},
		"key":  {ProfileId: 42, CertPem: []byte(bmcTestCertPEM)},
	} {
		t.Run(name, func(t *testing.T) {
			var c certCapture
			a, _ := adapterAgainst(t, c.handler(t, http.StatusOK, `{"success":true,"payload":{"status":"ok"}}`))
			err := a.Connection().Invoke(context.Background(),
				platformv1.BMCService_ReplaceWebCertificate_FullMethodName, req,
				&platformv1.BMCReplaceWebCertificateResponse{})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if c.hits != 0 {
				t.Errorf("API requests = %d, want 0", c.hits)
			}
		})
	}
}

const bmcTestMetaJSON = `{"subject":"CN=bmc","issuer":"CN=factory","serial_number":"12345",` +
	`"not_before":"2025-01-01T00:00:00Z","not_after":"2030-01-01T00:00:00Z",` +
	`"spki_sha256":"aa","sha256":"bb","captured_at":"2026-11-16T10:00:00Z"}`

const bmcTestStepsJSON = `[{"name":"trust","ok":true,"detail":"pinned"},` +
	`{"name":"factory-cert","ok":false,"detail":"failed"}]`

func checkBMCMeta(t *testing.T, meta *platformv1.BMCFactoryCertMeta) {
	t.Helper()
	if meta == nil {
		t.Fatal("certificate metadata is nil")
	}
	if meta.GetSubject() != "CN=bmc" || meta.GetIssuer() != "CN=factory" || meta.GetSerialNumber() != "12345" {
		t.Errorf("meta names = %q / %q / %q", meta.GetSubject(), meta.GetIssuer(), meta.GetSerialNumber())
	}
	if meta.GetSpkiSha256() != "aa" || meta.GetSha256() != "bb" {
		t.Errorf("meta digests = %q / %q", meta.GetSpkiSha256(), meta.GetSha256())
	}
	want := map[string]time.Time{
		"not_before":  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		"not_after":   time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		"captured_at": time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC),
	}
	got := map[string]time.Time{
		"not_before":  meta.GetNotBefore().AsTime(),
		"not_after":   meta.GetNotAfter().AsTime(),
		"captured_at": meta.GetCapturedAt().AsTime(),
	}
	for k, w := range want {
		if !got[k].Equal(w) {
			t.Errorf("meta %s = %v, want %v", k, got[k], w)
		}
	}
}

func checkBMCSteps(t *testing.T, steps []*platformv1.BMCEnrollStep) {
	t.Helper()
	if len(steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(steps))
	}
	if steps[0].GetName() != "trust" || !steps[0].GetOk() || steps[0].GetDetail() != "pinned" {
		t.Errorf("step 0 = %v", steps[0])
	}
	if steps[1].GetName() != "factory-cert" || steps[1].GetOk() || steps[1].GetDetail() != "failed" {
		t.Errorf("step 1 = %v", steps[1])
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestBMCEnroll_RouteAndReply(t *testing.T) {
	reply := `{"success":true,"payload":{"device_id":"7","endpoint":"bmc:443","hostname":"bmc",` +
		`"dns_name":"bmc.internal.","pin_spki_sha256":"cc",` +
		`"factory_cert_pem":` + jsonString(bmcTestCertPEM) + `,"factory_cert_meta":` + bmcTestMetaJSON + `,` +
		`"new_cert_pem":` + jsonString(bmcTestKeyPEM) + `,"ca_cert_pem":` + jsonString(bmcTestCAPEM) + `,` +
		`"steps":` + bmcTestStepsJSON + `}}`
	var c certCapture
	a, _ := adapterAgainst(t, c.handler(t, http.StatusOK, reply))

	req := &platformv1.BMCEnrollRequest{ProfileId: 42, RotatePassword: proto.Bool(false)}
	resp := &platformv1.BMCEnrollResponse{}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.BMCService_EnrollBMC_FullMethodName, req, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if c.method != http.MethodPost || c.path != "/api/v1/bmc/42/enroll" {
		t.Errorf("request = %s %s, want POST /api/v1/bmc/42/enroll", c.method, c.path)
	}
	if len(c.body) != 1 || c.body["rotate_password"] != false {
		t.Errorf("body = %v, want {rotate_password:false}", c.body)
	}
	if resp.GetDeviceId() != 7 || resp.GetEndpoint() != "bmc:443" || resp.GetHostname() != "bmc" {
		t.Errorf("device = %d %q %q", resp.GetDeviceId(), resp.GetEndpoint(), resp.GetHostname())
	}
	if resp.GetDnsName() != "bmc.internal." || resp.GetPinSpkiSha256() != "cc" {
		t.Errorf("dns/pin = %q %q", resp.GetDnsName(), resp.GetPinSpkiSha256())
	}
	if string(resp.GetFactoryCertPem()) != bmcTestCertPEM ||
		string(resp.GetNewCertPem()) != bmcTestKeyPEM ||
		string(resp.GetCaCertPem()) != bmcTestCAPEM {
		t.Errorf("PEM fields = %q / %q / %q", resp.GetFactoryCertPem(), resp.GetNewCertPem(), resp.GetCaCertPem())
	}
	checkBMCMeta(t, resp.GetFactoryCertMeta())
	checkBMCSteps(t, resp.GetSteps())
}

func TestBMCRestoreFactoryCert_RouteAndReply(t *testing.T) {
	reply := `{"success":true,"payload":{"device_id":"7","endpoint":"bmc:443","hostname":"bmc",` +
		`"new_cert_meta":` + bmcTestMetaJSON + `,"new_cert_pem":` + jsonString(bmcTestCertPEM) + `,` +
		`"steps":` + bmcTestStepsJSON + `}}`
	var c certCapture
	a, _ := adapterAgainst(t, c.handler(t, http.StatusOK, reply))

	resp := &platformv1.BMCRestoreResponse{}
	if err := a.Connection().Invoke(context.Background(),
		platformv1.BMCService_RestoreFactoryCert_FullMethodName,
		&platformv1.BMCRestoreRequest{ProfileId: 42}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if c.method != http.MethodPost || c.path != "/api/v1/bmc/42/cert/restore" {
		t.Errorf("request = %s %s, want POST /api/v1/bmc/42/cert/restore", c.method, c.path)
	}
	if len(c.body) != 0 {
		t.Errorf("body = %v, want no fields", c.body)
	}
	if resp.GetDeviceId() != 7 || resp.GetEndpoint() != "bmc:443" || resp.GetHostname() != "bmc" {
		t.Errorf("device = %d %q %q", resp.GetDeviceId(), resp.GetEndpoint(), resp.GetHostname())
	}
	if string(resp.GetNewCertPem()) != bmcTestCertPEM {
		t.Errorf("NewCertPem = %q", resp.GetNewCertPem())
	}
	checkBMCMeta(t, resp.GetNewCertMeta())
	checkBMCSteps(t, resp.GetSteps())
}

func TestBMCRestoreFactoryCert_UnavailableMapsCode(t *testing.T) {
	var c certCapture
	a, _ := adapterAgainst(t, c.handler(t, http.StatusServiceUnavailable,
		`{"success":false,"error":"BMC restorer not available"}`))

	err := a.Connection().Invoke(context.Background(),
		platformv1.BMCService_RestoreFactoryCert_FullMethodName,
		&platformv1.BMCRestoreRequest{ProfileId: 42}, &platformv1.BMCRestoreResponse{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
	if c.path != "/api/v1/bmc/42/cert/restore" {
		t.Errorf("path = %q, want /api/v1/bmc/42/cert/restore", c.path)
	}
}
