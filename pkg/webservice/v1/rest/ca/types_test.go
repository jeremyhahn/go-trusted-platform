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

package ca

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// PaginationParams Tests
// =============================================================================

func TestPaginationParams_JSON(t *testing.T) {
	t.Run("marshaling with all fields", func(t *testing.T) {
		params := PaginationParams{
			Limit:  50,
			Cursor: "abc123",
		}

		data, err := json.Marshal(params)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, float64(50), result["limit"])
		assert.Equal(t, "abc123", result["cursor"])
	})

	t.Run("unmarshaling with all fields", func(t *testing.T) {
		jsonData := `{"limit": 100, "cursor": "next-page-token"}`

		var params PaginationParams
		err := json.Unmarshal([]byte(jsonData), &params)
		require.NoError(t, err)

		assert.Equal(t, int32(100), params.Limit)
		assert.Equal(t, "next-page-token", params.Cursor)
	})

	t.Run("cursor omitted when empty", func(t *testing.T) {
		params := PaginationParams{
			Limit:  25,
			Cursor: "",
		}

		data, err := json.Marshal(params)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		_, hasCursor := result["cursor"]
		assert.False(t, hasCursor, "cursor should be omitted when empty")
	})

	t.Run("zero values", func(t *testing.T) {
		params := PaginationParams{}

		data, err := json.Marshal(params)
		require.NoError(t, err)

		var result PaginationParams
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, int32(0), result.Limit)
		assert.Equal(t, "", result.Cursor)
	})
}

// =============================================================================
// PaginatedResponse Tests
// =============================================================================

func TestPaginatedResponse_JSON(t *testing.T) {
	t.Run("marshaling with all fields", func(t *testing.T) {
		resp := PaginatedResponse{
			NextCursor: "page-2-token",
			HasMore:    true,
			TotalCount: 150,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "page-2-token", result["next_cursor"])
		assert.Equal(t, true, result["has_more"])
		assert.Equal(t, float64(150), result["total_count"])
	})

	t.Run("next_cursor omitted when empty", func(t *testing.T) {
		resp := PaginatedResponse{
			HasMore:    false,
			TotalCount: 10,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		_, hasNextCursor := result["next_cursor"]
		assert.False(t, hasNextCursor, "next_cursor should be omitted when empty")
	})

	t.Run("unmarshaling from JSON", func(t *testing.T) {
		jsonData := `{"next_cursor": "cursor-xyz", "has_more": true, "total_count": 500}`

		var resp PaginatedResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.Equal(t, "cursor-xyz", resp.NextCursor)
		assert.True(t, resp.HasMore)
		assert.Equal(t, int32(500), resp.TotalCount)
	})
}

// =============================================================================
// SubjectRequest Tests
// =============================================================================

func TestSubjectRequest_JSON(t *testing.T) {
	t.Run("marshaling full subject", func(t *testing.T) {
		subject := SubjectRequest{
			CommonName:         "example.com",
			Organization:       "Example Inc",
			OrganizationalUnit: "Engineering",
			Country:            "US",
			Province:           "California",
			Locality:           "San Francisco",
			Address:            "123 Main St",
			PostalCode:         "94105",
		}

		data, err := json.Marshal(subject)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "example.com", result["common_name"])
		assert.Equal(t, "Example Inc", result["organization"])
		assert.Equal(t, "Engineering", result["organizational_unit"])
		assert.Equal(t, "US", result["country"])
		assert.Equal(t, "California", result["province"])
		assert.Equal(t, "San Francisco", result["locality"])
		assert.Equal(t, "123 Main St", result["address"])
		assert.Equal(t, "94105", result["postal_code"])
	})

	t.Run("unmarshaling full subject", func(t *testing.T) {
		jsonData := `{
			"common_name": "test.example.com",
			"organization": "Test Org",
			"organizational_unit": "QA",
			"country": "UK",
			"province": "London",
			"locality": "Westminster",
			"address": "10 Downing St",
			"postal_code": "SW1A 2AA"
		}`

		var subject SubjectRequest
		err := json.Unmarshal([]byte(jsonData), &subject)
		require.NoError(t, err)

		assert.Equal(t, "test.example.com", subject.CommonName)
		assert.Equal(t, "Test Org", subject.Organization)
		assert.Equal(t, "QA", subject.OrganizationalUnit)
		assert.Equal(t, "UK", subject.Country)
		assert.Equal(t, "London", subject.Province)
		assert.Equal(t, "Westminster", subject.Locality)
		assert.Equal(t, "10 Downing St", subject.Address)
		assert.Equal(t, "SW1A 2AA", subject.PostalCode)
	})

	t.Run("optional fields omitted when empty", func(t *testing.T) {
		subject := SubjectRequest{
			CommonName: "minimal.example.com",
		}

		data, err := json.Marshal(subject)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "minimal.example.com", result["common_name"])

		// Check optional fields are omitted
		_, hasOrg := result["organization"]
		_, hasOU := result["organizational_unit"]
		assert.False(t, hasOrg, "organization should be omitted when empty")
		assert.False(t, hasOU, "organizational_unit should be omitted when empty")
	})

	t.Run("unmarshaling minimal subject", func(t *testing.T) {
		jsonData := `{"common_name": "simple.com"}`

		var subject SubjectRequest
		err := json.Unmarshal([]byte(jsonData), &subject)
		require.NoError(t, err)

		assert.Equal(t, "simple.com", subject.CommonName)
		assert.Empty(t, subject.Organization)
		assert.Empty(t, subject.OrganizationalUnit)
	})
}

// =============================================================================
// SANsRequest Tests
// =============================================================================

func TestSANsRequest_JSON(t *testing.T) {
	t.Run("marshaling with all SAN types", func(t *testing.T) {
		sans := SANsRequest{
			DNS:   []string{"example.com", "www.example.com"},
			IPs:   []string{"192.168.1.1", "10.0.0.1"},
			Email: []string{"admin@example.com", "security@example.com"},
			URIs:  []string{"https://example.com/callback", "spiffe://cluster.local/ns/default/sa/service"},
		}

		data, err := json.Marshal(sans)
		require.NoError(t, err)

		var result SANsRequest
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.ElementsMatch(t, sans.DNS, result.DNS)
		assert.ElementsMatch(t, sans.IPs, result.IPs)
		assert.ElementsMatch(t, sans.Email, result.Email)
		assert.ElementsMatch(t, sans.URIs, result.URIs)
	})

	t.Run("unmarshaling from JSON", func(t *testing.T) {
		jsonData := `{
			"dns": ["api.example.com"],
			"ips": ["127.0.0.1"],
			"email": ["test@example.com"],
			"uris": ["https://example.com"]
		}`

		var sans SANsRequest
		err := json.Unmarshal([]byte(jsonData), &sans)
		require.NoError(t, err)

		assert.Equal(t, []string{"api.example.com"}, sans.DNS)
		assert.Equal(t, []string{"127.0.0.1"}, sans.IPs)
		assert.Equal(t, []string{"test@example.com"}, sans.Email)
		assert.Equal(t, []string{"https://example.com"}, sans.URIs)
	})

	t.Run("empty SANs omits all fields", func(t *testing.T) {
		sans := SANsRequest{}

		data, err := json.Marshal(sans)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		_, hasDNS := result["dns"]
		_, hasIPs := result["ips"]
		_, hasEmail := result["email"]
		_, hasURIs := result["uris"]

		assert.False(t, hasDNS)
		assert.False(t, hasIPs)
		assert.False(t, hasEmail)
		assert.False(t, hasURIs)
	})

	t.Run("partial SANs", func(t *testing.T) {
		sans := SANsRequest{
			DNS: []string{"example.com"},
		}

		data, err := json.Marshal(sans)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.NotNil(t, result["dns"])
		_, hasIPs := result["ips"]
		assert.False(t, hasIPs)
	})
}

// =============================================================================
// CertificateIssueRequest Tests
// =============================================================================

func TestCertificateIssueRequest_JSON(t *testing.T) {
	t.Run("marshaling full request", func(t *testing.T) {
		req := CertificateIssueRequest{
			Subject: SubjectRequest{
				CommonName:   "server.example.com",
				Organization: "Example Corp",
			},
			SANs: &SANsRequest{
				DNS: []string{"server.example.com", "api.example.com"},
				IPs: []string{"192.168.1.100"},
			},
			ValidDays:    365,
			KeyAlgorithm: "ECDSA",
			StoreType:    "software",
			KeyUsage:     []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsage:  []string{"serverAuth", "clientAuth"},
			IsCA:         false,
			MaxPathLen:   0,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var result CertificateIssueRequest
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "server.example.com", result.Subject.CommonName)
		assert.Equal(t, 365, result.ValidDays)
		assert.Equal(t, "ECDSA", result.KeyAlgorithm)
		assert.NotNil(t, result.SANs)
		assert.Len(t, result.SANs.DNS, 2)
	})

	t.Run("unmarshaling minimal request", func(t *testing.T) {
		jsonData := `{
			"subject": {
				"common_name": "minimal.example.com"
			}
		}`

		var req CertificateIssueRequest
		err := json.Unmarshal([]byte(jsonData), &req)
		require.NoError(t, err)

		assert.Equal(t, "minimal.example.com", req.Subject.CommonName)
		assert.Nil(t, req.SANs)
		assert.Equal(t, 0, req.ValidDays)
		assert.Empty(t, req.KeyAlgorithm)
	})

	t.Run("CA certificate request", func(t *testing.T) {
		req := CertificateIssueRequest{
			Subject: SubjectRequest{
				CommonName:   "Intermediate CA",
				Organization: "Example CA",
			},
			ValidDays:    3650,
			KeyAlgorithm: "RSA4096",
			IsCA:         true,
			MaxPathLen:   1,
			KeyUsage:     []string{"certSign", "crlSign"},
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var result CertificateIssueRequest
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.True(t, result.IsCA)
		assert.Equal(t, 1, result.MaxPathLen)
		assert.Contains(t, result.KeyUsage, "certSign")
	})
}

// =============================================================================
// CertificateRevokeRequest Tests
// =============================================================================

func TestCertificateRevokeRequest_JSON(t *testing.T) {
	t.Run("marshaling with all fields", func(t *testing.T) {
		req := CertificateRevokeRequest{
			Reason:     1, // keyCompromise
			DeleteKeys: true,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, float64(1), result["reason"])
		assert.Equal(t, true, result["delete_keys"])
	})

	t.Run("unmarshaling from JSON", func(t *testing.T) {
		jsonData := `{"reason": 3, "delete_keys": false}`

		var req CertificateRevokeRequest
		err := json.Unmarshal([]byte(jsonData), &req)
		require.NoError(t, err)

		assert.Equal(t, 3, req.Reason)
		assert.False(t, req.DeleteKeys)
	})

	t.Run("empty request uses defaults", func(t *testing.T) {
		jsonData := `{}`

		var req CertificateRevokeRequest
		err := json.Unmarshal([]byte(jsonData), &req)
		require.NoError(t, err)

		assert.Equal(t, 0, req.Reason)
		assert.False(t, req.DeleteKeys)
	})
}

// =============================================================================
// CertificateResponse Tests
// =============================================================================

func TestCertificateResponse_JSON(t *testing.T) {
	t.Run("marshaling full response", func(t *testing.T) {
		resp := CertificateResponse{
			Serial: "abc123def456",
			Subject: SubjectRequest{
				CommonName:   "test.example.com",
				Organization: "Test Org",
			},
			Issuer:             "Intermediate CA",
			NotBefore:          1704067200, // 2024-01-01 00:00:00 UTC
			NotAfter:           1735689600, // 2025-01-01 00:00:00 UTC
			Status:             "VALID",
			KeyAlgorithm:       "ECDSA",
			SignatureAlgorithm: "ECDSA-SHA256",
			IsCA:               false,
			PEM:                "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CertificateResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "abc123def456", result.Serial)
		assert.Equal(t, "test.example.com", result.Subject.CommonName)
		assert.Equal(t, "Intermediate CA", result.Issuer)
		assert.Equal(t, int64(1704067200), result.NotBefore)
		assert.Equal(t, int64(1735689600), result.NotAfter)
		assert.Equal(t, "VALID", result.Status)
		assert.Equal(t, "ECDSA", result.KeyAlgorithm)
		assert.Contains(t, result.PEM, "BEGIN CERTIFICATE")
	})

	t.Run("PEM omitted when empty", func(t *testing.T) {
		resp := CertificateResponse{
			Serial:       "123",
			Status:       "VALID",
			KeyAlgorithm: "RSA",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		_, hasPEM := result["pem"]
		assert.False(t, hasPEM, "pem should be omitted when empty")
	})

	t.Run("different status values", func(t *testing.T) {
		statuses := []string{"VALID", "EXPIRED", "REVOKED", "NOT_YET_VALID"}

		for _, status := range statuses {
			resp := CertificateResponse{
				Serial: "test",
				Status: status,
			}

			data, err := json.Marshal(resp)
			require.NoError(t, err)

			var result CertificateResponse
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, status, result.Status)
		}
	})
}

// =============================================================================
// CertificateSummary Tests
// =============================================================================

func TestCertificateSummary_JSON(t *testing.T) {
	t.Run("marshaling full summary", func(t *testing.T) {
		summary := CertificateSummary{
			Serial:       "xyz789",
			CommonName:   "server.example.com",
			Issuer:       "Root CA",
			NotBefore:    1704067200,
			NotAfter:     1735689600,
			Status:       "VALID",
			KeyAlgorithm: "ECDSA",
		}

		data, err := json.Marshal(summary)
		require.NoError(t, err)

		var result CertificateSummary
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "xyz789", result.Serial)
		assert.Equal(t, "server.example.com", result.CommonName)
		assert.Equal(t, "Root CA", result.Issuer)
		assert.Equal(t, "VALID", result.Status)
	})

	t.Run("unmarshaling from JSON", func(t *testing.T) {
		jsonData := `{
			"serial": "aabbcc",
			"common_name": "api.example.com",
			"issuer": "Intermediate CA",
			"not_before": 1704067200,
			"not_after": 1735689600,
			"status": "EXPIRED",
			"key_algorithm": "RSA"
		}`

		var summary CertificateSummary
		err := json.Unmarshal([]byte(jsonData), &summary)
		require.NoError(t, err)

		assert.Equal(t, "aabbcc", summary.Serial)
		assert.Equal(t, "api.example.com", summary.CommonName)
		assert.Equal(t, "EXPIRED", summary.Status)
		assert.Equal(t, "RSA", summary.KeyAlgorithm)
	})
}

// =============================================================================
// CertificateListResponse Tests
// =============================================================================

func TestCertificateListResponse_JSON(t *testing.T) {
	t.Run("marshaling with certificates", func(t *testing.T) {
		resp := CertificateListResponse{
			PaginatedResponse: PaginatedResponse{
				NextCursor: "page2",
				HasMore:    true,
				TotalCount: 100,
			},
			Certificates: []CertificateSummary{
				{
					Serial:       "cert1",
					CommonName:   "server1.example.com",
					Status:       "VALID",
					KeyAlgorithm: "ECDSA",
				},
				{
					Serial:       "cert2",
					CommonName:   "server2.example.com",
					Status:       "VALID",
					KeyAlgorithm: "RSA",
				},
			},
			Timestamp: 1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CertificateListResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "page2", result.NextCursor)
		assert.True(t, result.HasMore)
		assert.Equal(t, int32(100), result.TotalCount)
		assert.Len(t, result.Certificates, 2)
		assert.Equal(t, int64(1704067200), result.Timestamp)
	})

	t.Run("empty certificate list", func(t *testing.T) {
		resp := CertificateListResponse{
			PaginatedResponse: PaginatedResponse{
				HasMore:    false,
				TotalCount: 0,
			},
			Certificates: []CertificateSummary{},
			Timestamp:    1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CertificateListResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.False(t, result.HasMore)
		assert.Equal(t, int32(0), result.TotalCount)
		assert.Empty(t, result.Certificates)
	})
}

// =============================================================================
// GetCertificateResponse Tests
// =============================================================================

func TestGetCertificateResponse_JSON(t *testing.T) {
	t.Run("marshaling with certificate", func(t *testing.T) {
		resp := GetCertificateResponse{
			Certificate: &CertificateResponse{
				Serial:       "test123",
				Status:       "VALID",
				KeyAlgorithm: "ECDSA",
			},
			Timestamp: 1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result GetCertificateResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		require.NotNil(t, result.Certificate)
		assert.Equal(t, "test123", result.Certificate.Serial)
		assert.Equal(t, int64(1704067200), result.Timestamp)
	})

	t.Run("nil certificate", func(t *testing.T) {
		resp := GetCertificateResponse{
			Certificate: nil,
			Timestamp:   1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Nil(t, result["certificate"])
	})
}

// =============================================================================
// IssueCertificateResponse Tests
// =============================================================================

func TestIssueCertificateResponse_JSON(t *testing.T) {
	t.Run("marshaling successful issue", func(t *testing.T) {
		resp := IssueCertificateResponse{
			Certificate: &CertificateResponse{
				Serial:       "newcert123",
				Status:       "VALID",
				KeyAlgorithm: "ECDSA",
				PEM:          "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
			},
			Timestamp: 1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result IssueCertificateResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		require.NotNil(t, result.Certificate)
		assert.Equal(t, "newcert123", result.Certificate.Serial)
		assert.Contains(t, result.Certificate.PEM, "BEGIN CERTIFICATE")
	})
}

// =============================================================================
// RevokeCertificateResponse Tests
// =============================================================================

func TestRevokeCertificateResponse_JSON(t *testing.T) {
	t.Run("marshaling revocation response", func(t *testing.T) {
		resp := RevokeCertificateResponse{
			Serial:    "revoked123",
			Status:    "REVOKED",
			RevokedAt: 1704067200,
			Reason:    1, // keyCompromise
			Timestamp: 1704067300,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result RevokeCertificateResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "revoked123", result.Serial)
		assert.Equal(t, "REVOKED", result.Status)
		assert.Equal(t, int64(1704067200), result.RevokedAt)
		assert.Equal(t, 1, result.Reason)
	})

	t.Run("unmarshaling from JSON", func(t *testing.T) {
		jsonData := `{
			"serial": "abc123",
			"status": "REVOKED",
			"revoked_at": 1704067200,
			"reason": 3,
			"timestamp": 1704067300
		}`

		var resp RevokeCertificateResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.Equal(t, "abc123", resp.Serial)
		assert.Equal(t, 3, resp.Reason)
	})
}

// =============================================================================
// CAInfoResponse Tests
// =============================================================================

func TestCAInfoResponse_JSON(t *testing.T) {
	t.Run("marshaling full CA info", func(t *testing.T) {
		resp := CAInfoResponse{
			CommonName:       "Test Root CA",
			IsInitialized:    true,
			IsIntermediate:   false,
			DefaultAlgorithm: "ECDSA",
			DefaultValidity:  365,
			Timestamp:        1704067200,
			RootCert: &CertificateSummary{
				Serial:       "root123",
				CommonName:   "Test Root CA",
				Status:       "VALID",
				KeyAlgorithm: "ECDSA",
			},
			Intermediates: []CertificateSummary{},
			KeyStores: []KeyStoreInfo{
				{
					Type:         "software",
					Available:    true,
					Capabilities: []string{"sign", "verify"},
				},
			},
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CAInfoResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "Test Root CA", result.CommonName)
		assert.True(t, result.IsInitialized)
		assert.False(t, result.IsIntermediate)
		assert.NotNil(t, result.RootCert)
		assert.Equal(t, "root123", result.RootCert.Serial)
	})

	t.Run("uninitialized CA", func(t *testing.T) {
		resp := CAInfoResponse{
			IsInitialized: false,
			Timestamp:     1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CAInfoResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.False(t, result.IsInitialized)
		assert.Nil(t, result.RootCert)
	})

	t.Run("intermediate CA", func(t *testing.T) {
		resp := CAInfoResponse{
			CommonName:     "Intermediate CA",
			IsInitialized:  true,
			IsIntermediate: true,
			Intermediates: []CertificateSummary{
				{
					Serial:     "int123",
					CommonName: "Intermediate CA",
					Status:     "VALID",
				},
			},
			Timestamp: 1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CAInfoResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.True(t, result.IsIntermediate)
		assert.Len(t, result.Intermediates, 1)
	})
}

// =============================================================================
// KeyStoreInfo Tests
// =============================================================================

func TestKeyStoreInfo_JSON(t *testing.T) {
	t.Run("marshaling with capabilities", func(t *testing.T) {
		info := KeyStoreInfo{
			Type:         "tpm2",
			Available:    true,
			Capabilities: []string{"sign", "verify", "encrypt", "decrypt"},
		}

		data, err := json.Marshal(info)
		require.NoError(t, err)

		var result KeyStoreInfo
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "tpm2", result.Type)
		assert.True(t, result.Available)
		assert.Len(t, result.Capabilities, 4)
	})

	t.Run("unavailable keystore", func(t *testing.T) {
		info := KeyStoreInfo{
			Type:      "pkcs11",
			Available: false,
		}

		data, err := json.Marshal(info)
		require.NoError(t, err)

		var result KeyStoreInfo
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "pkcs11", result.Type)
		assert.False(t, result.Available)
		assert.Empty(t, result.Capabilities)
	})
}

// =============================================================================
// RevokedCertEntry Tests
// =============================================================================

func TestRevokedCertEntry_JSON(t *testing.T) {
	t.Run("marshaling revoked entry", func(t *testing.T) {
		entry := RevokedCertEntry{
			Serial:         "revoked456",
			RevocationTime: 1704067200,
			Reason:         1, // keyCompromise
		}

		data, err := json.Marshal(entry)
		require.NoError(t, err)

		var result RevokedCertEntry
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "revoked456", result.Serial)
		assert.Equal(t, int64(1704067200), result.RevocationTime)
		assert.Equal(t, 1, result.Reason)
	})

	t.Run("different revocation reasons", func(t *testing.T) {
		reasons := []int{0, 1, 2, 3, 4, 5, 6, 9, 10} // RFC 5280 reason codes

		for _, reason := range reasons {
			entry := RevokedCertEntry{
				Serial:         "test",
				RevocationTime: 1704067200,
				Reason:         reason,
			}

			data, err := json.Marshal(entry)
			require.NoError(t, err)

			var result RevokedCertEntry
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, reason, result.Reason)
		}
	})
}

// =============================================================================
// CRLResponse Tests
// =============================================================================

func TestCRLResponse_JSON(t *testing.T) {
	t.Run("marshaling CRL response", func(t *testing.T) {
		resp := CRLResponse{
			CRL:          []byte{0x30, 0x82, 0x01, 0x00}, // Sample DER bytes
			LastUpdate:   1704067200,
			NextUpdate:   1704153600,
			RevokedCount: 2,
			RevokedCerts: []RevokedCertEntry{
				{Serial: "rev1", RevocationTime: 1704000000, Reason: 1},
				{Serial: "rev2", RevocationTime: 1704050000, Reason: 3},
			},
			Timestamp: 1704067300,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CRLResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.NotEmpty(t, result.CRL)
		assert.Equal(t, int64(1704067200), result.LastUpdate)
		assert.Equal(t, int64(1704153600), result.NextUpdate)
		assert.Equal(t, 2, result.RevokedCount)
		assert.Len(t, result.RevokedCerts, 2)
	})

	t.Run("empty CRL", func(t *testing.T) {
		resp := CRLResponse{
			CRL:          []byte{},
			LastUpdate:   1704067200,
			NextUpdate:   1704153600,
			RevokedCount: 0,
			RevokedCerts: nil,
			Timestamp:    1704067300,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result CRLResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Empty(t, result.RevokedCerts)
		assert.Equal(t, 0, result.RevokedCount)
	})
}

// =============================================================================
// BundleResponse Tests
// =============================================================================

func TestBundleResponse_JSON(t *testing.T) {
	t.Run("marshaling bundle response", func(t *testing.T) {
		resp := BundleResponse{
			Bundle: []byte("-----BEGIN CERTIFICATE-----\n...root...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n...intermediate...\n-----END CERTIFICATE-----"),
			Certificates: []CertificateSummary{
				{Serial: "root1", CommonName: "Root CA", Status: "VALID"},
				{Serial: "int1", CommonName: "Intermediate CA", Status: "VALID"},
			},
			CertCount: 2,
			Timestamp: 1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result BundleResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.NotEmpty(t, result.Bundle)
		assert.Equal(t, 2, result.CertCount)
		assert.Len(t, result.Certificates, 2)
	})

	t.Run("empty bundle", func(t *testing.T) {
		resp := BundleResponse{
			Bundle:       []byte{},
			Certificates: []CertificateSummary{},
			CertCount:    0,
			Timestamp:    1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result BundleResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Empty(t, result.Bundle)
		assert.Equal(t, 0, result.CertCount)
	})
}

// =============================================================================
// SuccessResponse Tests
// =============================================================================

func TestSuccessResponse_JSON(t *testing.T) {
	t.Run("marshaling success response", func(t *testing.T) {
		resp := SuccessResponse{
			Success:   true,
			Message:   "Operation completed successfully",
			Timestamp: 1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result SuccessResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.True(t, result.Success)
		assert.Equal(t, "Operation completed successfully", result.Message)
		assert.Equal(t, int64(1704067200), result.Timestamp)
	})

	t.Run("failure response", func(t *testing.T) {
		resp := SuccessResponse{
			Success:   false,
			Message:   "Operation failed",
			Timestamp: 1704067200,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result SuccessResponse
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.False(t, result.Success)
		assert.Equal(t, "Operation failed", result.Message)
	})

	t.Run("message omitted when empty", func(t *testing.T) {
		resp := SuccessResponse{
			Success: true,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		_, hasMessage := result["message"]
		assert.False(t, hasMessage, "message should be omitted when empty")
	})
}
