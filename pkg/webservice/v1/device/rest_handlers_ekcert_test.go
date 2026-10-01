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

package device

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// newEKCertPEMForWebserviceTest generates a self-signed ECDSA certificate
// PEM used to exercise the profile EK-cert prestage path.
func newEKCertPEMForWebserviceTest(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestCRUDHandler_CreateProfile_EKPrestageFields verifies the webservice
// create path persists the device-identity, EK-cert prestage, config, and
// assignment fields (transport parity with gRPC).
func TestCRUDHandler_CreateProfile_EKPrestageFields(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	certPEM := newEKCertPEMForWebserviceTest(t)
	assignedAt := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

	reqBody := ProfileRequest{
		ID:         77,
		Name:       "ek-profile",
		Role:       "server",
		EKSerial:   "EK-WS-1",
		EKCert:     certPEM,
		MACAddress: "aa:bb:cc:dd:ee:11",
		Config:     map[string]any{"hostname": "node-02"},
		Assigned:   true,
		AssignedAt: assignedAt,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/device/profiles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	stored := profileSvc.profiles[77]
	require.NotNil(t, stored)
	assert.Equal(t, "EK-WS-1", stored.EKSerial)
	assert.Equal(t, certPEM, stored.EKCert)
	assert.Equal(t, "aa:bb:cc:dd:ee:11", stored.MACAddress)
	assert.True(t, stored.Assigned)
	assert.Equal(t, assignedAt, stored.AssignedAt)

	var resp ProfileFullResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, certPEM, resp.EKCert, "EK cert is public material and must be echoed for auditability")
	assert.Equal(t, "EK-WS-1", resp.EKSerial)
	assert.Equal(t, "aa:bb:cc:dd:ee:11", resp.MACAddress)
	assert.True(t, resp.Assigned)
}

// TestCRUDHandler_CreateProfile_InvalidEKCert verifies the webservice
// create path rejects an unparseable EK certificate with 400 and stores
// nothing.
func TestCRUDHandler_CreateProfile_InvalidEKCert(t *testing.T) {
	handler, _, profileSvc := newTestHandler()

	body := `{"id": 78, "name": "bad-ek", "ek_cert": "not a pem certificate"}`
	req := httptest.NewRequest(http.MethodPost, "/device/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Nil(t, profileSvc.profiles[78])
}

// TestCRUDHandler_UpdateProfile_EKPrestageFields verifies the webservice
// update path replaces the stored profile with the request payload,
// including the EK prestage fields.
func TestCRUDHandler_UpdateProfile_EKPrestageFields(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "prestage-target"}
	certPEM := newEKCertPEMForWebserviceTest(t)

	reqBody := ProfileRequest{
		Name:       "prestage-target",
		EKSerial:   "EK-WS-2",
		EKCert:     certPEM,
		MACAddress: "aa:bb:cc:dd:ee:22",
		Config:     map[string]any{"hostname": "node-03"},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/device/profiles/1", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	stored := profileSvc.profiles[1]
	require.NotNil(t, stored)
	assert.Equal(t, "EK-WS-2", stored.EKSerial)
	assert.Equal(t, certPEM, stored.EKCert)
	assert.Equal(t, "aa:bb:cc:dd:ee:22", stored.MACAddress)
}

// TestCRUDHandler_UpdateProfile_InvalidEKCert verifies the webservice
// update path rejects an unparseable EK certificate with 400 without
// touching the stored profile.
func TestCRUDHandler_UpdateProfile_InvalidEKCert(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "keep-clean"}

	body := `{"name": "keep-clean", "ek_cert": "garbage"}`
	req := httptest.NewRequest(http.MethodPut, "/device/profiles/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, profileSvc.profiles[1].EKCert)
}
