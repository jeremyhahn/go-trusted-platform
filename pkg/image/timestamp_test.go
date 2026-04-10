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

package image

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRFC3161Client(t *testing.T) {
	tests := []struct {
		name      string
		tsaURL    string
		expectErr bool
	}{
		{
			name:      "valid URL",
			tsaURL:    "https://timestamp.example.com",
			expectErr: false,
		},
		{
			name:      "empty URL",
			tsaURL:    "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewRFC3161Client(tt.tsaURL)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestNewRFC3161Client_WithOptions(t *testing.T) {
	pool := x509.NewCertPool()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	customTime := func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	client, err := NewRFC3161Client(
		"https://timestamp.example.com",
		WithTrustedCAs(pool),
		WithHTTPClient(httpClient),
		WithCurrentTime(customTime),
	)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, pool, client.trustedCAs)
	assert.Equal(t, httpClient, client.httpClient)
	assert.Equal(t, customTime(), client.currentTime())
}

func TestRFC3161Client_Timestamp_NilData(t *testing.T) {
	client, err := NewRFC3161Client("https://timestamp.example.com")
	require.NoError(t, err)

	_, err = client.Timestamp(context.Background(), nil)
	assert.Error(t, err)

	_, err = client.Timestamp(context.Background(), []byte{})
	assert.Error(t, err)
}

func TestRFC3161Client_Timestamp_MockServer(t *testing.T) {
	// Create a mock TSA response
	mockResponse := TimestampResponse{
		Status: PKIStatusInfo{
			Status: 0, // Granted
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: []byte{0x30, 0x00}, // Minimal ASN.1 SEQUENCE
		},
	}

	respBytes, err := asn1.Marshal(mockResponse)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/timestamp-query", r.Header.Get("Content-Type"))

		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(respBytes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	client, err := NewRFC3161Client(server.URL)
	require.NoError(t, err)

	data := []byte("test data to timestamp")
	token, err := client.Timestamp(context.Background(), data)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestRFC3161Client_Timestamp_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("internal server error")); err != nil {
			return
		}
	}))
	defer server.Close()

	client, err := NewRFC3161Client(server.URL)
	require.NoError(t, err)

	_, err = client.Timestamp(context.Background(), []byte("test data"))
	assert.Error(t, err)
	assert.IsType(t, ErrTimestampFailed{}, err)
}

func TestRFC3161Client_Timestamp_RejectedResponse(t *testing.T) {
	// Create a rejected TSA response without StatusString to avoid ASN1 marshaling issues
	// Real TSA responses would have proper ASN1 encoding
	mockResponse := TimestampResponse{
		Status: PKIStatusInfo{
			Status: 2, // Rejected
		},
	}

	respBytes, err := asn1.Marshal(mockResponse)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(respBytes); err != nil {
			return
		}
	}))
	defer server.Close()

	client, err := NewRFC3161Client(server.URL)
	require.NoError(t, err)

	_, err = client.Timestamp(context.Background(), []byte("test data"))
	assert.Error(t, err)
	assert.IsType(t, ErrTimestampFailed{}, err)
}

func TestRFC3161Client_Timestamp_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("not valid asn1")); err != nil {
			return
		}
	}))
	defer server.Close()

	client, err := NewRFC3161Client(server.URL)
	require.NoError(t, err)

	_, err = client.Timestamp(context.Background(), []byte("test data"))
	assert.Error(t, err)
	assert.IsType(t, ErrTimestampFailed{}, err)
}

func TestRFC3161Client_Verify_NilParams(t *testing.T) {
	client, err := NewRFC3161Client("https://timestamp.example.com")
	require.NoError(t, err)

	_, err = client.Verify(context.Background(), nil, []byte("data"))
	assert.Error(t, err)
	assert.IsType(t, ErrNilParameter{}, err)

	_, err = client.Verify(context.Background(), []byte("token"), nil)
	assert.Error(t, err)
	assert.IsType(t, ErrNilParameter{}, err)

	_, err = client.Verify(context.Background(), []byte{}, []byte("data"))
	assert.Error(t, err)
	assert.IsType(t, ErrNilParameter{}, err)

	_, err = client.Verify(context.Background(), []byte("token"), []byte{})
	assert.Error(t, err)
	assert.IsType(t, ErrNilParameter{}, err)
}

func TestRFC3161Client_Verify_InvalidToken(t *testing.T) {
	client, err := NewRFC3161Client("https://timestamp.example.com")
	require.NoError(t, err)

	tests := []struct {
		name  string
		token []byte
	}{
		{
			name:  "not ASN.1",
			token: []byte("not valid asn1"),
		},
		{
			name:  "minimal sequence",
			token: []byte{0x30, 0x00},
		},
		{
			name:  "wrong content type",
			token: mustMarshalContentInfo(t, asn1.ObjectIdentifier{1, 2, 3}, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Verify(context.Background(), tt.token, []byte("data"))
			assert.Error(t, err)
		})
	}
}

func TestRFC3161Client_Verify_ValidToken(t *testing.T) {
	// Create a test key pair for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a self-signed TSA certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TSA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Test data
	data := []byte("test data to timestamp")
	digest := sha256.Sum256(data)

	// Create TSTInfo
	tstInfo := TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: digest[:],
		},
		SerialNumber: big.NewInt(12345),
		GenTime:      time.Now().UTC().Truncate(time.Second),
		Accuracy: Accuracy{
			Seconds: 1,
			Millis:  500,
		},
	}

	tstInfoBytes, err := asn1.Marshal(tstInfo)
	require.NoError(t, err)

	// Create timestamp token
	token := createTestTimestampToken(t, tstInfoBytes, cert, privateKey)

	// Create client and verify
	client, err := NewRFC3161Client("https://timestamp.example.com")
	require.NoError(t, err)

	info, err := client.Verify(context.Background(), token, data)
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "SHA256", info.HashAlgorithm)
	assert.Equal(t, tstInfo.GenTime.UTC(), info.Time.UTC())
	assert.Equal(t, "Test TSA", info.TSAName)
	assert.Equal(t, digest[:], info.MessageImprint)
}

func TestRFC3161Client_Verify_MessageImprintMismatch(t *testing.T) {
	// Create a test key pair for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a self-signed TSA certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test TSA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Create token with different data digest
	wrongDigest := sha256.Sum256([]byte("different data"))

	tstInfo := TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: wrongDigest[:],
		},
		SerialNumber: big.NewInt(12345),
		GenTime:      time.Now().UTC().Truncate(time.Second),
	}

	tstInfoBytes, err := asn1.Marshal(tstInfo)
	require.NoError(t, err)

	token := createTestTimestampToken(t, tstInfoBytes, cert, privateKey)

	client, err := NewRFC3161Client("https://timestamp.example.com")
	require.NoError(t, err)

	_, err = client.Verify(context.Background(), token, []byte("original data"))
	assert.Error(t, err)
	assert.IsType(t, ErrMessageImprintMismatch{}, err)
}

func TestRFC3161Client_Verify_WithTrustedCAs(t *testing.T) {
	// Create CA key and certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Create TSA key and certificate signed by CA
	tsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tsaTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test TSA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	tsaCertDER, err := x509.CreateCertificate(rand.Reader, tsaTemplate, caCert, &tsaKey.PublicKey, caKey)
	require.NoError(t, err)

	tsaCert, err := x509.ParseCertificate(tsaCertDER)
	require.NoError(t, err)

	// Test data
	data := []byte("test data")
	digest := sha256.Sum256(data)

	tstInfo := TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: digest[:],
		},
		SerialNumber: big.NewInt(12345),
		GenTime:      time.Now().UTC().Truncate(time.Second),
	}

	tstInfoBytes, err := asn1.Marshal(tstInfo)
	require.NoError(t, err)

	token := createTestTimestampTokenWithChain(t, tstInfoBytes, tsaCert, caCert, tsaKey)

	// Create trusted CA pool
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	client, err := NewRFC3161Client("https://timestamp.example.com", WithTrustedCAs(caPool))
	require.NoError(t, err)

	info, err := client.Verify(context.Background(), token, data)
	require.NoError(t, err)
	assert.NotNil(t, info)
}

func TestRFC3161Client_Verify_ECDSASignature(t *testing.T) {
	// Create ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test TSA ECDSA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Test data
	data := []byte("test data for ECDSA")
	digest := sha256.Sum256(data)

	tstInfo := TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: digest[:],
		},
		SerialNumber: big.NewInt(12345),
		GenTime:      time.Now().UTC().Truncate(time.Second),
	}

	tstInfoBytes, err := asn1.Marshal(tstInfo)
	require.NoError(t, err)

	token := createTestTimestampTokenECDSA(t, tstInfoBytes, cert, privateKey)

	client, err := NewRFC3161Client("https://timestamp.example.com")
	require.NoError(t, err)

	info, err := client.Verify(context.Background(), token, data)
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "SHA256", info.HashAlgorithm)
}

func TestNoOpTimestampClient(t *testing.T) {
	client := NewNoOpTimestampClient()
	assert.NotNil(t, client)

	// Timestamp should return nil
	token, err := client.Timestamp(context.Background(), []byte("data"))
	assert.NoError(t, err)
	assert.Nil(t, token)

	// Verify should return nil
	info, err := client.Verify(context.Background(), []byte("token"), []byte("data"))
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestTimestampClientInterface(t *testing.T) {
	// Verify RFC3161Client implements TimestampClient
	var _ TimestampClient = &RFC3161Client{}

	// Verify NoOpTimestampClient implements TimestampClient
	var _ TimestampClient = &NoOpTimestampClient{}
}

func TestTimestampRequest_Encoding(t *testing.T) {
	req := TimestampRequest{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: []byte("test hash"),
		},
		CertReq: true,
	}

	// Should encode without error
	encoded, err := asn1.Marshal(req)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Should decode back
	var decoded TimestampRequest
	_, err = asn1.Unmarshal(encoded, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, req.Version, decoded.Version)
	assert.Equal(t, req.CertReq, decoded.CertReq)
}

func TestTimestampResponse_Decoding(t *testing.T) {
	// Create response without StatusString to avoid ASN1 marshaling issues
	// Real TSA responses would have proper ASN1 encoding
	resp := TimestampResponse{
		Status: PKIStatusInfo{
			Status: 0,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: []byte{0x30, 0x00},
		},
	}

	encoded, err := asn1.Marshal(resp)
	require.NoError(t, err)

	var decoded TimestampResponse
	_, err = asn1.Unmarshal(encoded, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, 0, decoded.Status.Status)
}

func TestPKIStatusInfo_StatusValues(t *testing.T) {
	tests := []struct {
		status      int
		description string
	}{
		{0, "granted"},
		{1, "grantedWithMods"},
		{2, "rejection"},
		{3, "waiting"},
		{4, "revocationWarning"},
		{5, "revocationNotification"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			status := PKIStatusInfo{
				Status: tt.status,
			}

			encoded, err := asn1.Marshal(status)
			assert.NoError(t, err)

			var decoded PKIStatusInfo
			_, err = asn1.Unmarshal(encoded, &decoded)
			assert.NoError(t, err)
			assert.Equal(t, tt.status, decoded.Status)
		})
	}
}

func TestMessageImprint_Encoding(t *testing.T) {
	mi := MessageImprint{
		HashAlgorithm: AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		HashedMessage: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		},
	}

	encoded, err := asn1.Marshal(mi)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	var decoded MessageImprint
	_, err = asn1.Unmarshal(encoded, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, mi.HashedMessage, decoded.HashedMessage)
}

func TestAlgorithmIdentifier_OIDs(t *testing.T) {
	// Test SHA-256 OID
	assert.Equal(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, oidSHA256)
	// Test SHA-384 OID
	assert.Equal(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, oidSHA384)
	// Test SHA-512 OID
	assert.Equal(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, oidSHA512)
}

func TestTimestampInfo_Fields(t *testing.T) {
	info := &TimestampInfo{
		SerialNumber:   []byte{0x01, 0x02, 0x03},
		HashAlgorithm:  "SHA256",
		TSAName:        "Test TSA",
		PolicyID:       "1.2.3.4.5",
		MessageImprint: []byte{0x01, 0x02, 0x03, 0x04},
		Nonce:          []byte{0x05, 0x06},
		Accuracy:       time.Second + 500*time.Millisecond,
	}

	assert.Equal(t, []byte{0x01, 0x02, 0x03}, info.SerialNumber)
	assert.Equal(t, "SHA256", info.HashAlgorithm)
	assert.Equal(t, "Test TSA", info.TSAName)
	assert.Equal(t, "1.2.3.4.5", info.PolicyID)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, info.MessageImprint)
	assert.Equal(t, []byte{0x05, 0x06}, info.Nonce)
	assert.Equal(t, time.Second+500*time.Millisecond, info.Accuracy)
}

func TestAccuracy_ToDuration(t *testing.T) {
	tests := []struct {
		name     string
		accuracy Accuracy
		expected time.Duration
	}{
		{
			name:     "seconds only",
			accuracy: Accuracy{Seconds: 5},
			expected: 5 * time.Second,
		},
		{
			name:     "milliseconds only",
			accuracy: Accuracy{Millis: 500},
			expected: 500 * time.Millisecond,
		},
		{
			name:     "microseconds only",
			accuracy: Accuracy{Micros: 100},
			expected: 100 * time.Microsecond,
		},
		{
			name:     "combined",
			accuracy: Accuracy{Seconds: 1, Millis: 500, Micros: 100},
			expected: time.Second + 500*time.Millisecond + 100*time.Microsecond,
		},
		{
			name:     "zero",
			accuracy: Accuracy{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.accuracy.ToDuration())
		})
	}
}

func TestTSTInfo_Encoding(t *testing.T) {
	tstInfo := TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: []byte{0x01, 0x02, 0x03},
		},
		SerialNumber: big.NewInt(12345),
		GenTime:      time.Now().UTC().Truncate(time.Second),
		Accuracy: Accuracy{
			Seconds: 1,
		},
		Ordering: false,
	}

	encoded, err := asn1.Marshal(tstInfo)
	require.NoError(t, err)

	var decoded TSTInfo
	_, err = asn1.Unmarshal(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, tstInfo.Version, decoded.Version)
	assert.True(t, tstInfo.Policy.Equal(decoded.Policy))
	assert.Equal(t, tstInfo.MessageImprint.HashedMessage, decoded.MessageImprint.HashedMessage)
	assert.Equal(t, 0, tstInfo.SerialNumber.Cmp(decoded.SerialNumber))
	assert.Equal(t, tstInfo.GenTime.UTC(), decoded.GenTime.UTC())
}

func TestParseASN1Length(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectedLen int
		expectedHdr int
		expectErr   bool
	}{
		{
			name:        "short form",
			data:        []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expectedLen: 5,
			expectedHdr: 2,
		},
		{
			name:        "long form 1 byte",
			data:        []byte{0x30, 0x81, 0x80},
			expectedLen: 128,
			expectedHdr: 3,
		},
		{
			name:        "long form 2 bytes",
			data:        []byte{0x30, 0x82, 0x01, 0x00},
			expectedLen: 256,
			expectedHdr: 4,
		},
		{
			name:      "too short",
			data:      []byte{0x30},
			expectErr: true,
		},
		{
			name:      "invalid encoding",
			data:      []byte{0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, header, err := parseASN1Length(tt.data)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedLen, length)
				assert.Equal(t, tt.expectedHdr, header)
			}
		})
	}
}

// Helper functions for test token creation

func mustMarshalContentInfo(t *testing.T, contentType asn1.ObjectIdentifier, content []byte) []byte {
	ci := contentInfo{
		ContentType: contentType,
	}
	if content != nil {
		ci.Content = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      content,
		}
	}

	data, err := asn1.Marshal(ci)
	require.NoError(t, err)
	return data
}

func createTestTimestampToken(t *testing.T, tstInfoBytes []byte, cert *x509.Certificate, key *rsa.PrivateKey) []byte {
	// Create content type attribute
	contentTypeValue, err := asn1.Marshal(oidContentTypeTST)
	require.NoError(t, err)
	contentTypeSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      contentTypeValue,
	})
	require.NoError(t, err)

	// Create message digest attribute
	tstInfoDigest := sha256.Sum256(tstInfoBytes)
	messageDigestValue, err := asn1.Marshal(tstInfoDigest[:])
	require.NoError(t, err)
	messageDigestSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      messageDigestValue,
	})
	require.NoError(t, err)

	// Build authenticated attributes
	attrs := []attribute{
		{
			Type:   oidAttributeContentType,
			Values: asn1.RawValue{FullBytes: contentTypeSet},
		},
		{
			Type:   oidAttributeMessageDigest,
			Values: asn1.RawValue{FullBytes: messageDigestSet},
		},
	}

	// Encode attributes for signing
	var attrBytes []byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		require.NoError(t, err)
		attrBytes = append(attrBytes, encoded...)
	}

	attrSetBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      attrBytes,
	})
	require.NoError(t, err)

	// Sign the attributes
	attrHash := sha256.Sum256(attrSetBytes)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, attrHash[:])
	require.NoError(t, err)

	// Build signer info
	si := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		AuthenticatedAttributes: attrs,
		DigestEncryptionAlgorithm: AlgorithmIdentifier{
			Algorithm: oidRSAEncryption,
		},
		EncryptedDigest: signature,
	}

	// Build SignedData
	sd := signedData{
		Version: 1,
		DigestAlgorithmIdentifiers: []AlgorithmIdentifier{
			{Algorithm: oidSHA256},
		},
		ContentInfo: contentInfo{
			ContentType: oidContentTypeTST,
			Content: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      tstInfoBytes,
			},
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      cert.Raw,
		},
		SignerInfos: []signerInfo{si},
	}

	sdBytes, err := asn1.Marshal(sd)
	require.NoError(t, err)

	// Wrap in ContentInfo
	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	tokenBytes, err := asn1.Marshal(ci)
	require.NoError(t, err)

	return tokenBytes
}

func createTestTimestampTokenWithChain(t *testing.T, tstInfoBytes []byte, tsaCert, caCert *x509.Certificate, key *rsa.PrivateKey) []byte {
	// Create content type attribute
	contentTypeValue, err := asn1.Marshal(oidContentTypeTST)
	require.NoError(t, err)
	contentTypeSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      contentTypeValue,
	})
	require.NoError(t, err)

	// Create message digest attribute
	tstInfoDigest := sha256.Sum256(tstInfoBytes)
	messageDigestValue, err := asn1.Marshal(tstInfoDigest[:])
	require.NoError(t, err)
	messageDigestSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      messageDigestValue,
	})
	require.NoError(t, err)

	// Build authenticated attributes
	attrs := []attribute{
		{
			Type:   oidAttributeContentType,
			Values: asn1.RawValue{FullBytes: contentTypeSet},
		},
		{
			Type:   oidAttributeMessageDigest,
			Values: asn1.RawValue{FullBytes: messageDigestSet},
		},
	}

	// Encode attributes for signing
	var attrBytes []byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		require.NoError(t, err)
		attrBytes = append(attrBytes, encoded...)
	}

	attrSetBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      attrBytes,
	})
	require.NoError(t, err)

	// Sign the attributes
	attrHash := sha256.Sum256(attrSetBytes)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, attrHash[:])
	require.NoError(t, err)

	// Build signer info
	si := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: tsaCert.RawIssuer},
			SerialNumber: tsaCert.SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		AuthenticatedAttributes: attrs,
		DigestEncryptionAlgorithm: AlgorithmIdentifier{
			Algorithm: oidRSAEncryption,
		},
		EncryptedDigest: signature,
	}

	// Build certificate chain
	certChainBytes := append(tsaCert.Raw, caCert.Raw...)

	// Build SignedData
	sd := signedData{
		Version: 1,
		DigestAlgorithmIdentifiers: []AlgorithmIdentifier{
			{Algorithm: oidSHA256},
		},
		ContentInfo: contentInfo{
			ContentType: oidContentTypeTST,
			Content: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      tstInfoBytes,
			},
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certChainBytes,
		},
		SignerInfos: []signerInfo{si},
	}

	sdBytes, err := asn1.Marshal(sd)
	require.NoError(t, err)

	// Wrap in ContentInfo
	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	tokenBytes, err := asn1.Marshal(ci)
	require.NoError(t, err)

	return tokenBytes
}

func createTestTimestampTokenECDSA(t *testing.T, tstInfoBytes []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	// Create content type attribute
	contentTypeValue, err := asn1.Marshal(oidContentTypeTST)
	require.NoError(t, err)
	contentTypeSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      contentTypeValue,
	})
	require.NoError(t, err)

	// Create message digest attribute
	tstInfoDigest := sha256.Sum256(tstInfoBytes)
	messageDigestValue, err := asn1.Marshal(tstInfoDigest[:])
	require.NoError(t, err)
	messageDigestSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      messageDigestValue,
	})
	require.NoError(t, err)

	// Build authenticated attributes
	attrs := []attribute{
		{
			Type:   oidAttributeContentType,
			Values: asn1.RawValue{FullBytes: contentTypeSet},
		},
		{
			Type:   oidAttributeMessageDigest,
			Values: asn1.RawValue{FullBytes: messageDigestSet},
		},
	}

	// Encode attributes for signing
	var attrBytes []byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		require.NoError(t, err)
		attrBytes = append(attrBytes, encoded...)
	}

	attrSetBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      attrBytes,
	})
	require.NoError(t, err)

	// Sign the attributes with ECDSA
	attrHash := sha256.Sum256(attrSetBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, key, attrHash[:])
	require.NoError(t, err)

	// Build signer info
	si := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		AuthenticatedAttributes: attrs,
		DigestEncryptionAlgorithm: AlgorithmIdentifier{
			Algorithm: oidECDSAWithSHA256,
		},
		EncryptedDigest: signature,
	}

	// Build SignedData
	sd := signedData{
		Version: 1,
		DigestAlgorithmIdentifiers: []AlgorithmIdentifier{
			{Algorithm: oidSHA256},
		},
		ContentInfo: contentInfo{
			ContentType: oidContentTypeTST,
			Content: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      tstInfoBytes,
			},
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      cert.Raw,
		},
		SignerInfos: []signerInfo{si},
	}

	sdBytes, err := asn1.Marshal(sd)
	require.NoError(t, err)

	// Wrap in ContentInfo
	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	tokenBytes, err := asn1.Marshal(ci)
	require.NoError(t, err)

	return tokenBytes
}
