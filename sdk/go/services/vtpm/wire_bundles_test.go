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

package vtpm

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDecodeGetBundleJSON(t *testing.T) {
	t.Run("bare bundle", func(t *testing.T) {
		resp, err := DecodeGetBundleJSON([]byte(
			`{"id":"b1","mode":"template","manifest":{"hostname":"node-1","ek_algorithm":"ECC"}}`))

		require.NoError(t, err)
		assert.Equal(t, "b1", resp.GetBundle().GetId())
		assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_TEMPLATE, resp.GetBundle().GetMode())
		assert.Equal(t, "node-1", resp.GetBundle().GetManifest().GetHostname())
		assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, resp.GetBundle().GetManifest().GetEkAlgorithm())
	})
	t.Run("daemon flat bundle", func(t *testing.T) {
		// The JSON field set of the daemon's BundleResponse
		// (pkg/api/rest/vtpm_handlers.go), which carries the manifest
		// fields at the top level and secure-boot key fingerprints.
		type ekCert struct {
			Subject      string    `json:"subject"`
			Issuer       string    `json:"issuer"`
			SerialNumber string    `json:"serial_number"`
			NotBefore    time.Time `json:"not_before"`
			NotAfter     time.Time `json:"not_after"`
			Fingerprint  string    `json:"fingerprint"`
		}
		type sbKeys struct {
			PKFingerprint  string `json:"pk_fingerprint"`
			KEKFingerprint string `json:"kek_fingerprint"`
			DBFingerprint  string `json:"db_fingerprint"`
		}
		type daemonBundle struct {
			ID                string            `json:"id"`
			Mode              string            `json:"mode"`
			Hostname          string            `json:"hostname,omitempty"`
			EKAlgorithm       string            `json:"ek_algorithm"`
			SecureBootEnabled bool              `json:"secure_boot_enabled"`
			Running           bool              `json:"running"`
			CreatedAt         time.Time         `json:"created_at"`
			ClonedFrom        string            `json:"cloned_from,omitempty"`
			Labels            map[string]string `json:"labels,omitempty"`
			SocketPath        string            `json:"socket_path,omitempty"`
			EKCertificate     *ekCert           `json:"ek_certificate,omitempty"`
			SecureBootKeys    *sbKeys           `json:"secure_boot_keys,omitempty"`
		}
		notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		created := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
		body, err := json.Marshal(daemonBundle{
			ID:                "b2",
			Mode:              "pre-assigned",
			Hostname:          "node-2",
			EKAlgorithm:       "RSA",
			SecureBootEnabled: true,
			Running:           true,
			CreatedAt:         created,
			ClonedFrom:        "b1",
			Labels:            map[string]string{"env": "test"},
			EKCertificate: &ekCert{
				Subject:      "CN=ek",
				Issuer:       "CN=ca",
				SerialNumber: "42",
				NotBefore:    notBefore,
				NotAfter:     notBefore.AddDate(1, 0, 0),
				Fingerprint:  "ek-fp",
			},
			SecureBootKeys: &sbKeys{PKFingerprint: "pk-fp", KEKFingerprint: "kek-fp", DBFingerprint: "db-fp"},
		})
		require.NoError(t, err)

		resp, err := DecodeGetBundleJSON(body)

		require.NoError(t, err)
		bundle := resp.GetBundle()
		assert.Equal(t, "b2", bundle.GetId())
		assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, bundle.GetMode())
		assert.Equal(t, "b1", bundle.GetClonedFrom())
		assert.True(t, created.Equal(bundle.GetCreatedAt().AsTime()))
		manifest := bundle.GetManifest()
		require.NotNil(t, manifest)
		assert.Equal(t, "b2", manifest.GetId())
		assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, manifest.GetMode())
		assert.Equal(t, "node-2", manifest.GetHostname())
		assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_RSA, manifest.GetEkAlgorithm())
		assert.True(t, manifest.GetSecureBootEnabled())
		assert.Equal(t, map[string]string{"env": "test"}, manifest.GetLabels())
		assert.Equal(t, "b1", manifest.GetClonedFrom())
		cert := manifest.GetEkCertificate()
		require.NotNil(t, cert)
		assert.Equal(t, "CN=ek", cert.GetSubject())
		assert.Equal(t, "CN=ca", cert.GetIssuer())
		assert.Equal(t, "42", cert.GetSerialNumber())
		assert.Equal(t, "ek-fp", cert.GetFingerprint())
		assert.True(t, notBefore.Equal(cert.GetNotBefore().AsTime()))
		keys := manifest.GetSecureBootKeys()
		require.NotNil(t, keys)
		assert.Equal(t, "pk-fp", keys.GetPkFingerprint())
		assert.Equal(t, "kek-fp", keys.GetKekFingerprint())
		assert.Equal(t, "db-fp", keys.GetDbFingerprint())
		assert.Nil(t, bundle.GetSecureBootKeys(), "fingerprints must not land in the key path fields")
	})
	t.Run("daemon bundle without manifest", func(t *testing.T) {
		resp, err := DecodeGetBundleJSON([]byte(
			`{"id":"b3","mode":"template","ek_algorithm":"","secure_boot_enabled":false,"running":false}`))

		require.NoError(t, err)
		assert.Equal(t, "b3", resp.GetBundle().GetId())
		assert.Nil(t, resp.GetBundle().GetManifest())
		assert.Nil(t, resp.GetBundle().GetSecureBootKeys())
	})
	t.Run("malformed JSON", func(t *testing.T) {
		_, err := DecodeGetBundleJSON([]byte(`{"id":`))

		var decodeErr *ErrWireDecode
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, "get bundle", decodeErr.Message)
	})
	t.Run("unknown bundle mode", func(t *testing.T) {
		_, err := DecodeGetBundleJSON([]byte(`{"id":"b1","mode":"cloned"}`))

		var unknown *ErrUnknownWireValue
		require.ErrorAs(t, err, &unknown)
		assert.Equal(t, "cloned", unknown.Value)
	})
}

func TestDecodeValidateBundleJSON(t *testing.T) {
	t.Run("valid bundle", func(t *testing.T) {
		resp, err := DecodeValidateBundleJSON([]byte(`{"valid":true}`))

		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.True(t, resp.GetValid())
		assert.Empty(t, resp.GetErrors())
	})
	t.Run("invalid bundle keeps its errors", func(t *testing.T) {
		resp, err := DecodeValidateBundleJSON([]byte(
			`{"valid":false,"errors":["nvram missing","ek cert expired"]}`))

		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.False(t, resp.GetValid())
		assert.Equal(t, []string{"nvram missing", "ek cert expired"}, resp.GetErrors())
	})
	t.Run("daemon reply carries a timestamp", func(t *testing.T) {
		resp, err := DecodeValidateBundleJSON([]byte(
			`{"valid":false,"errors":["bad"],"timestamp":"2025-01-02T03:04:05Z"}`))

		require.NoError(t, err)
		assert.False(t, resp.GetValid())
		assert.Equal(t, []string{"bad"}, resp.GetErrors())
	})
	t.Run("malformed JSON", func(t *testing.T) {
		_, err := DecodeValidateBundleJSON([]byte(`{"valid":"yes"}`))

		var decodeErr *ErrWireDecode
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, "validate bundle", decodeErr.Message)
	})
}
