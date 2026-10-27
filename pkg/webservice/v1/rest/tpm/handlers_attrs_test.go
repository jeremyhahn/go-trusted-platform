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

package tpm_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tpm"
)

var errCommandsRefused = errors.New("TPM_RC_VALUE")

// attrsTPM answers the capability, platform, extend and credential calls
// the five routes below reach through TPMService.
type attrsTPM struct {
	xkmssdk.TrustedPlatformModule
	cmdErr      error
	extended    []int
	madeFor     []byte
	activations int
}

func (a *attrsTPM) SupportedAlgorithms() ([]string, error) { return []string{"RSA"}, nil }
func (a *attrsTPM) SupportedCommands() ([]string, error)   { return []string{"TPM2_Quote"}, a.cmdErr }
func (a *attrsTPM) SupportedECCCurves() ([]string, error)  { return []string{"NIST_P256"}, nil }
func (a *attrsTPM) Device() string                         { return "/dev/tpmrm0" }
func (a *attrsTPM) IsFIPS140_2() (bool, error)             { return false, nil }
func (a *attrsTPM) IsPlatformPCRExtended() (bool, error)   { return true, nil }
func (a *attrsTPM) CanSeal() bool                          { return true }
func (a *attrsTPM) Config() *xkmssdk.TPMConfig             { return nil }
func (a *attrsTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return &xkmssdk.PropertiesFixed{Manufacturer: "IFX"}, nil
}
func (a *attrsTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		TPMAttributes: &xkmssdk.TPMAttributes{Handle: 0x81010001},
	}, nil
}
func (a *attrsTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) { return nil, errCommandsRefused }
func (a *attrsTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error)  { return nil, errCommandsRefused }
func (a *attrsTPM) ExtendPCR(pcrIndex int, _ string, _ []byte) error {
	a.extended = append(a.extended, pcrIndex)
	return nil
}
func (a *attrsTPM) MakeCredential(akName tpmgo.TPM2BName, secret []byte) ([]byte, []byte, []byte, error) {
	a.madeFor = akName.Buffer
	return []byte("blob"), []byte("encrypted"), secret, nil
}
func (a *attrsTPM) ActivateCredential(_, _ []byte) ([]byte, error) {
	a.activations++
	return []byte("secret"), nil
}

func serveAttrs(t *testing.T, device *attrsTPM, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	server := daemon.NewTPMGRPCService(logger)
	server.SetTPM2Service(device)
	parent := mux.NewRouter()
	tpm.NewTPMRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	w := httptest.NewRecorder()
	parent.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w
}

func payloadOf(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var envelope struct {
		Payload map[string]any `json:"payload"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&envelope))
	return envelope.Payload
}

func TestCapabilities_ReturnsTheThreeLists(t *testing.T) {
	w := serveAttrs(t, &attrsTPM{}, http.MethodGet, "/api/v1/tpm/capabilities", "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	payload := payloadOf(t, w)
	assert.Equal(t, []any{"RSA"}, payload["algorithms"])
	assert.Equal(t, []any{"TPM2_Quote"}, payload["commands"])
	assert.Equal(t, []any{"NIST_P256"}, payload["eccCurves"])
}

func TestCapabilities_RefusedListIsAClientError(t *testing.T) {
	w := serveAttrs(t, &attrsTPM{cmdErr: errCommandsRefused}, http.MethodGet, "/api/v1/tpm/capabilities", "")

	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "commands")
}

func TestPlatformAttributes_DescribesTheDevice(t *testing.T) {
	w := serveAttrs(t, &attrsTPM{}, http.MethodGet, "/api/v1/tpm/platform", "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	payload := payloadOf(t, w)
	assert.Equal(t, "/dev/tpmrm0", payload["device"])
	assert.Equal(t, "IFX", payload["manufacturer"])
	assert.Equal(t, true, payload["pcrExtended"])
	assert.Equal(t, map[string]any{"handle": float64(0x81010001), "algorithm": "RSA"}, payload["ek"])
	assert.Nil(t, payload["iak"], "an IAK that is not provisioned is absent")
}

func TestPlatformAttributes_RefusesWithoutATPM(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	parent := mux.NewRouter()
	tpm.NewTPMRouter(logger, daemon.NewTPMGRPCService(logger), response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	w := httptest.NewRecorder()

	parent.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/tpm/platform", nil))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestExtendPCR_ExtendsTheIndex(t *testing.T) {
	device := &attrsTPM{}

	w := serveAttrs(t, device, http.MethodPost, "/api/v1/tpm/pcrs/extend", `{"index":16,"data":"bWVhc3VyZW1lbnQ="}`)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []int{16}, device.extended)
}

func TestExtendPCR_RefusesABadRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"undecodable body", `{"index":`},
		{"index past 23", `{"index":24,"data":"eA=="}`},
		{"no data", `{"index":16}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &attrsTPM{}

			w := serveAttrs(t, device, http.MethodPost, "/api/v1/tpm/pcrs/extend", tt.body)

			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Empty(t, device.extended, "the TPM must not be extended")
		})
	}
}

func TestMakeCredential_WrapsTheSecret(t *testing.T) {
	device := &attrsTPM{}

	w := serveAttrs(t, device, http.MethodPost, "/api/v1/tpm/make-credential", `{"akName":"YWs=","secret":"c2VjcmV0"}`)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []byte("ak"), device.madeFor)
	assert.Equal(t, "YmxvYg==", payloadOf(t, w)["credentialBlob"])
}

func TestMakeCredential_RefusesAnUndecodableBody(t *testing.T) {
	device := &attrsTPM{}

	w := serveAttrs(t, device, http.MethodPost, "/api/v1/tpm/make-credential", `{"akName":`)

	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Nil(t, device.madeFor)
}

func TestActivateCredential_RecoversTheSecret(t *testing.T) {
	device := &attrsTPM{}

	w := serveAttrs(t, device, http.MethodPost, "/api/v1/tpm/activate-credential",
		`{"credentialBlob":"YmxvYg==","encryptedSecret":"ZW5j"}`)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "c2VjcmV0", payloadOf(t, w)["secret"])
	assert.Equal(t, 1, device.activations)
}

func TestActivateCredential_RefusesAMissingBlob(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"undecodable body", `{"credentialBlob":`},
		{"no blob", `{"encryptedSecret":"ZW5j"}`},
		{"no encrypted secret", `{"credentialBlob":"YmxvYg=="}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &attrsTPM{}

			w := serveAttrs(t, device, http.MethodPost, "/api/v1/tpm/activate-credential", tt.body)

			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Zero(t, device.activations, "the TPM must not be asked to activate")
		})
	}
}
