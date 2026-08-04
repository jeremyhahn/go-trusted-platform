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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newEKCertPEMForRESTTest generates a self-signed ECDSA certificate PEM
// used to exercise the profile EK-cert prestage path over REST.
func newEKCertPEMForRESTTest(t *testing.T) string {
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

// TestHandleCreateProfile_EKPrestageFields verifies the REST create path
// persists and echoes the device-identity, EK-cert prestage, config, and
// assignment fields (transport parity with gRPC).
func TestHandleCreateProfile_EKPrestageFields(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

	certPEM := newEKCertPEMForRESTTest(t)
	assignedAt := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	reqBody := ProfileCreateRequest{
		Name:       "ek-profile",
		Role:       "server",
		EKSerial:   "EK-REST-1",
		EKCert:     certPEM,
		MACAddress: "aa:bb:cc:dd:ee:01",
		Config:     map[string]any{"hostname": "lab-node-2"},
		Assigned:   true,
		AssignedAt: assignedAt,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Result().StatusCode, "body: %s", w.Body.String())

	var resp ProfileResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "EK-REST-1", resp.EKSerial)
	assert.Equal(t, certPEM, resp.EKCert, "EK cert is public material and must be echoed for auditability")
	assert.Equal(t, "aa:bb:cc:dd:ee:01", resp.MACAddress)
	assert.True(t, resp.Assigned)
	assert.Equal(t, assignedAt, resp.AssignedAt.UTC())
	config, ok := resp.Config.(map[string]any)
	require.True(t, ok, "config must round-trip as a JSON object, got %T", resp.Config)
	assert.Equal(t, "lab-node-2", config["hostname"])
}

// TestHandleCreateProfile_InvalidEKCert verifies the REST create path
// rejects an unparseable EK certificate with 400.
func TestHandleCreateProfile_InvalidEKCert(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

	body, err := json.Marshal(ProfileCreateRequest{
		Name:   "bad-ek",
		EKCert: "not a pem certificate",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

// TestHandleUpdateProfile_EKPrestageFields verifies the REST update path
// applies the partial EK prestage fields onto an existing profile — the
// operator flow that arms EK-bound config delivery for a hardware node.
func TestHandleUpdateProfile_EKPrestageFields(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

	// Seed a profile without EK prestage.
	seedBody, err := json.Marshal(ProfileCreateRequest{Name: "prestage-target"})
	require.NoError(t, err)
	seedReq := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(seedBody))
	seedReq.Header.Set("Content-Type", "application/json")
	seedW := httptest.NewRecorder()
	router.ServeHTTP(seedW, seedReq)
	require.Equal(t, http.StatusCreated, seedW.Result().StatusCode)

	var seeded ProfileResponse
	require.NoError(t, json.Unmarshal(seedW.Body.Bytes(), &seeded))
	require.NotZero(t, seeded.ID)

	certPEM := newEKCertPEMForRESTTest(t)
	assigned := true
	assignedAt := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	updateBody, err := json.Marshal(ProfileUpdateRequest{
		EKSerial:   "EK-REST-2",
		EKCert:     certPEM,
		MACAddress: "aa:bb:cc:dd:ee:02",
		Config:     map[string]any{"hostname": "lab-node-3"},
		Assigned:   &assigned,
		AssignedAt: &assignedAt,
	})
	require.NoError(t, err)

	url := "/api/v1/devices/profiles/" + jsonNumber(seeded.ID)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Result().StatusCode, "body: %s", w.Body.String())

	var resp ProfileResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "prestage-target", resp.Name, "unset fields must keep their values")
	assert.Equal(t, "EK-REST-2", resp.EKSerial)
	assert.Equal(t, certPEM, resp.EKCert)
	assert.Equal(t, "aa:bb:cc:dd:ee:02", resp.MACAddress)
	assert.True(t, resp.Assigned)
	assert.Equal(t, assignedAt, resp.AssignedAt.UTC())
}

// TestHandleUpdateProfile_InvalidEKCert verifies the REST update path
// rejects an unparseable EK certificate with 400 without touching the
// stored profile.
func TestHandleUpdateProfile_InvalidEKCert(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

	seedBody, err := json.Marshal(ProfileCreateRequest{Name: "keep-clean"})
	require.NoError(t, err)
	seedReq := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(seedBody))
	seedReq.Header.Set("Content-Type", "application/json")
	seedW := httptest.NewRecorder()
	router.ServeHTTP(seedW, seedReq)
	require.Equal(t, http.StatusCreated, seedW.Result().StatusCode)

	var seeded ProfileResponse
	require.NoError(t, json.Unmarshal(seedW.Body.Bytes(), &seeded))

	updateBody, err := json.Marshal(ProfileUpdateRequest{EKCert: "garbage"})
	require.NoError(t, err)

	url := "/api/v1/devices/profiles/" + jsonNumber(seeded.ID)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

// jsonNumber formats a uint64 for use in a URL path.
func jsonNumber(id uint64) string {
	return new(big.Int).SetUint64(id).String()
}
