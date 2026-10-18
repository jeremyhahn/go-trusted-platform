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

package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// postCeremonyREST posts body to path on the daemon's ceremony routes,
// served over the fake backend, and returns the status and response body.
func postCeremonyREST(t *testing.T, path, body string) (int, []byte) {
	t.Helper()
	router := mux.NewRouter()
	newCeremonyRESTHandlers(NewCeremonyService(nil, &fakeCeremonyBackend{})).registerCeremonyRoutes(router)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	out, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read %s response: %v", path, err)
	}
	return rec.Code, out
}

// decodeCeremonyWire decodes a REST response the way the platform SDK's REST
// transport does: protojson into the platform.v1 response message.
func decodeCeremonyWire(t *testing.T, body []byte, out proto.Message) {
	t.Helper()
	if err := protojson.Unmarshal(body, out); err != nil {
		t.Fatalf("decode %s as %T: %v", body, out, err)
	}
}

// The issued certificate and chain reach the caller under the platform.v1
// CeremonySignCSRResponse field names, so the SDK decodes what the backend
// signed.
func TestCeremonyREST_SignCSR_CarriesTheSignedCertificate(t *testing.T) {
	code, body := postCeremonyREST(t, "/ceremony/sign-csr",
		`{"username":"alice","so_pin":"pin","csr_pem":"CSR","role":"admin"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body %s; want 200", code, body)
	}
	var resp platformv1.CeremonySignCSRResponse
	decodeCeremonyWire(t, body, &resp)
	if resp.GetCertificatePem() != "SIGNED" || resp.GetChainPem() != "CHAIN" {
		t.Fatalf("response = %s, want certificate SIGNED and chain CHAIN", body)
	}
}

func TestCeremonyREST_SignCSR_RefusesAMissingCSR(t *testing.T) {
	code, body := postCeremonyREST(t, "/ceremony/sign-csr", `{"username":"alice"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s; want 400", code, body)
	}
}

// The officer certificate a completed claim issues reaches the caller under
// the platform.v1 CeremonyClaimCertCompleteResponse field names.
func TestCeremonyREST_ClaimCertComplete_CarriesTheOfficerCertificate(t *testing.T) {
	code, body := postCeremonyREST(t, "/ceremony/claim-cert/complete",
		`{"username":"alice","nonce":"n","signature":"s"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body %s; want 200", code, body)
	}
	var resp platformv1.CeremonyClaimCertCompleteResponse
	decodeCeremonyWire(t, body, &resp)
	if resp.GetCertificatePem() != "CERT" || resp.GetChainPem() != "CHAIN" {
		t.Fatalf("response = %s, want certificate CERT and chain CHAIN", body)
	}
}

func TestCeremonyREST_ClaimCertComplete_RefusesAMissingSignature(t *testing.T) {
	code, body := postCeremonyREST(t, "/ceremony/claim-cert/complete", `{"username":"alice","nonce":"n"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s; want 400", code, body)
	}
}
