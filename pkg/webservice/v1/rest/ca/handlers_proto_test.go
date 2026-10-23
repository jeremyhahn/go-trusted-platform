package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustAnchorEndpoint describes one of the two CA trust-anchor endpoints,
// GET /ca/root and GET /ca/intermediate, which share their whole contract
// and differ only in which certificate the CA is asked for.
type trustAnchorEndpoint struct {
	name   string
	path   string
	serve  func(h *CAHandlers, w http.ResponseWriter, r *http.Request)
	stubCA func(cert *x509.Certificate, err error) *mockCertificateAuthority
}

var trustAnchorEndpoints = []trustAnchorEndpoint{
	{
		name:  "root",
		path:  "/api/v1/ca/root",
		serve: (*CAHandlers).GetRoot,
		stubCA: func(cert *x509.Certificate, err error) *mockCertificateAuthority {
			return &mockCertificateAuthority{
				initialized:   true,
				trustedRootFn: func() (*x509.Certificate, error) { return cert, err },
			}
		},
	},
	{
		name:  "intermediate",
		path:  "/api/v1/ca/intermediate",
		serve: (*CAHandlers).GetIntermediate,
		stubCA: func(cert *x509.Certificate, err error) *mockCertificateAuthority {
			return &mockCertificateAuthority{
				initialized:           true,
				trustedIntermediateFn: func() (*x509.Certificate, error) { return cert, err },
			}
		},
	},
}

func serveTrustAnchor(t *testing.T, ep trustAnchorEndpoint, ca *mockCertificateAuthority) (*httptest.ResponseRecorder, *mockHttpWriter) {
	t.Helper()
	var handlers *CAHandlers
	var writer *mockHttpWriter
	if ca == nil {
		handlers, writer = newTestHandlers(nil)
	} else {
		handlers, writer = newTestHandlers(ca)
	}
	rec := httptest.NewRecorder()
	ep.serve(handlers, rec, httptest.NewRequest(http.MethodGet, ep.path, nil))
	return rec, writer
}

func TestTrustAnchorEndpoints_Success(t *testing.T) {
	// Whole seconds, so the protojson timestamp and RFC 3339 agree exactly.
	now := time.Now().Truncate(time.Second)
	statuses := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      string
	}{
		{"valid", now.Add(-time.Hour), now.Add(time.Hour), "CERTIFICATE_STATUS_VALID"},
		{"not yet valid", now.Add(time.Hour), now.Add(2 * time.Hour), "CERTIFICATE_STATUS_PENDING"},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), "CERTIFICATE_STATUS_EXPIRED"},
	}

	for _, ep := range trustAnchorEndpoints {
		for _, st := range statuses {
			t.Run(ep.name+"/"+st.name, func(t *testing.T) {
				cert := createTestIntermediateCertificate()
				cert.NotBefore = st.notBefore
				cert.NotAfter = st.notAfter

				rec, writer := serveTrustAnchor(t, ep, ep.stubCA(cert, nil))

				require.Equal(t, http.StatusOK, writer.lastStatus)
				payload := decodeProtoBody(t, rec)
				assert.Equal(t, hex.EncodeToString(cert.SerialNumber.Bytes()), payload["serial"])
				assert.Equal(t, "Test Intermediate CA", payload["commonName"])
				assert.Equal(t, "Test Root CA", payload["issuer"])
				assert.Equal(t, st.want, payload["status"])
				assert.Equal(t, "KEY_ALGORITHM_ECDSA_P256", payload["keyAlgorithm"])
				assert.Equal(t, cert.NotAfter.UTC().Format(time.RFC3339Nano), payload["notAfter"])
			})
		}
	}
}

func TestTrustAnchorEndpoints_Errors(t *testing.T) {
	for _, ep := range trustAnchorEndpoints {
		t.Run(ep.name+"/no CA", func(t *testing.T) {
			_, writer := serveTrustAnchor(t, ep, nil)
			assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
		})

		t.Run(ep.name+"/CA lookup fails", func(t *testing.T) {
			_, writer := serveTrustAnchor(t, ep, ep.stubCA(nil, errors.New("keystore sealed")))
			assert.Equal(t, http.StatusNotFound, writer.lastStatus)
			require.Error(t, writer.lastError)
			assert.Contains(t, writer.lastError.Error(), ErrCANotInitialized{}.Error())
		})

		t.Run(ep.name+"/CA has no certificate", func(t *testing.T) {
			_, writer := serveTrustAnchor(t, ep, ep.stubCA(nil, nil))
			assert.Equal(t, http.StatusNotFound, writer.lastStatus)
			require.Error(t, writer.lastError)
			assert.Contains(t, writer.lastError.Error(), ErrCANotInitialized{}.Error())
		})
	}
}

// issueSANCertificate returns a real, parsed self-signed certificate that
// carries every subject field and every SAN kind certToProto copies.
func issueSANCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffe, err := url.Parse("spiffe://platform.example/node/1")
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x0a0b0c),
		Subject: pkix.Name{
			CommonName:         "node-1.platform.example",
			Organization:       []string{"Platform"},
			OrganizationalUnit: []string{"tenant-a"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Jose"},
			StreetAddress:      []string{"1 Main St"},
			PostalCode:         []string{"95112"},
		},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:       []string{"node-1.platform.example"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("fd00::1")},
		EmailAddresses: []string{"ops@platform.example"},
		URIs:           []*url.URL{spiffe},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestCertToProto(t *testing.T) {
	handlers, _ := newTestHandlers(&mockCertificateAuthority{})

	t.Run("copies subject, SANs, usages and fingerprint", func(t *testing.T) {
		cert := issueSANCertificate(t)

		out := handlers.certToProto(cert, false, false)

		require.NotNil(t, out)
		assert.Equal(t, "0a0b0c", out.Serial)
		assert.Equal(t, &platformv1.Subject{
			CommonName:         "node-1.platform.example",
			Organization:       "Platform",
			OrganizationalUnit: "tenant-a",
			Country:            "US",
			Province:           "CA",
			Locality:           "San Jose",
			Address:            "1 Main St",
			PostalCode:         "95112",
		}, out.Subject)
		assert.Equal(t, "node-1.platform.example", out.Issuer)
		assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, out.Status)
		assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, out.KeyAlgorithm)
		assert.Equal(t, "ECDSA-SHA256", out.SignatureAlgorithm)
		assert.Equal(t, []string{"DIGITAL_SIGNATURE"}, out.KeyUsage)
		assert.Equal(t, []string{"SERVER_AUTH", "CLIENT_AUTH"}, out.ExtKeyUsage)
		fingerprint := sha256.Sum256(cert.Raw)
		assert.Equal(t, hex.EncodeToString(fingerprint[:]), out.FingerprintSha256)

		require.NotNil(t, out.Sans)
		assert.Equal(t, []string{"node-1.platform.example"}, out.Sans.DnsNames)
		assert.Equal(t, []string{"10.0.0.1", "fd00::1"}, out.Sans.IpAddresses)
		assert.Equal(t, []string{"ops@platform.example"}, out.Sans.EmailAddresses)
		assert.Equal(t, []string{"spiffe://platform.example/node/1"}, out.Sans.Uris)

		assert.Empty(t, out.Pem, "PEM was not requested")
		assert.Empty(t, out.Der, "DER was not requested")
	})

	t.Run("includes PEM and DER of the raw certificate on request", func(t *testing.T) {
		cert := issueSANCertificate(t)

		out := handlers.certToProto(cert, true, true)

		block, rest := pem.Decode(out.Pem)
		require.NotNil(t, block, "PEM does not decode")
		assert.Empty(t, rest)
		assert.Equal(t, "CERTIFICATE", block.Type)
		assert.Equal(t, cert.Raw, block.Bytes)
		assert.Equal(t, cert.Raw, out.Der)
	})

	t.Run("omits SANs and PEM when the certificate has neither", func(t *testing.T) {
		cert := createTestCertificate("bare.example")

		out := handlers.certToProto(cert, true, false)

		assert.Nil(t, out.Sans)
		assert.Empty(t, out.Pem, "a certificate without Raw bytes has no PEM")
	})

	t.Run("nil certificate", func(t *testing.T) {
		assert.Nil(t, handlers.certToProto(nil, true, true))
		assert.Nil(t, handlers.certToSummaryProto(nil))
	})
}

func TestKeyUsageToStrings(t *testing.T) {
	handlers, _ := newTestHandlers(nil)

	t.Run("every bit in RFC 5280 order", func(t *testing.T) {
		all := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
			x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign |
			x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly
		assert.Equal(t, []string{
			"DIGITAL_SIGNATURE", "CONTENT_COMMITMENT", "KEY_ENCIPHERMENT",
			"DATA_ENCIPHERMENT", "KEY_AGREEMENT", "CERT_SIGN", "CRL_SIGN",
			"ENCIPHER_ONLY", "DECIPHER_ONLY",
		}, handlers.keyUsageToStrings(all))
	})

	t.Run("no usage", func(t *testing.T) {
		assert.Empty(t, handlers.keyUsageToStrings(0))
	})
}

func TestExtKeyUsageToStrings(t *testing.T) {
	handlers, _ := newTestHandlers(nil)

	t.Run("every named usage", func(t *testing.T) {
		assert.Equal(t, []string{
			"ANY", "SERVER_AUTH", "CLIENT_AUTH", "CODE_SIGNING",
			"EMAIL_PROTECTION", "TIME_STAMPING", "OCSP_SIGNING",
		}, handlers.extKeyUsageToStrings([]x509.ExtKeyUsage{
			x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning,
		}))
	})

	t.Run("usages without a name are dropped", func(t *testing.T) {
		assert.Equal(t, []string{"SERVER_AUTH"}, handlers.extKeyUsageToStrings([]x509.ExtKeyUsage{
			x509.ExtKeyUsageIPSECEndSystem, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageMicrosoftKernelCodeSigning,
		}))
		assert.Empty(t, handlers.extKeyUsageToStrings(nil))
	})
}

func TestKeyAlgorithmToProto(t *testing.T) {
	handlers, _ := newTestHandlers(nil)
	cases := []struct {
		alg  x509.PublicKeyAlgorithm
		want platformv1.KeyAlgorithm
	}{
		{x509.RSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048},
		{x509.ECDSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256},
		{x509.Ed25519, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519},
		{x509.DSA, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
		{x509.UnknownPublicKeyAlgorithm, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, handlers.keyAlgorithmToProto(tc.alg))
		})
	}
}

// TestRevocationReasonToProto maps every CRLReason code of RFC 5280 §5.3.1.
// Code 7 is unassigned there, so it and any out-of-range code are reported
// as unspecified rather than guessed at.
func TestRevocationReasonToProto(t *testing.T) {
	handlers, _ := newTestHandlers(nil)
	cases := []struct {
		code int
		want platformv1.RevocationReason
	}{
		{0, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
		{1, platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE},
		{2, platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE},
		{3, platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED},
		{4, platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED},
		{5, platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION},
		{6, platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD},
		{7, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
		{8, platformv1.RevocationReason_REVOCATION_REASON_REMOVE_FROM_CRL},
		{9, platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN},
		{10, platformv1.RevocationReason_REVOCATION_REASON_AA_COMPROMISE},
		{11, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
		{-1, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.want.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, handlers.revocationReasonToProto(tc.code))
		})
	}
}

func TestProtoKeyAlgorithmToX509(t *testing.T) {
	handlers, _ := newTestHandlers(nil)

	t.Run("every defined algorithm", func(t *testing.T) {
		cases := map[platformv1.KeyAlgorithm]x509.PublicKeyAlgorithm{
			platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED: x509.ECDSA,
			platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:    x509.RSA,
			platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:    x509.RSA,
			platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:    x509.RSA,
			platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:  x509.ECDSA,
			platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:  x509.ECDSA,
			platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:  x509.ECDSA,
			platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519:     x509.Ed25519,
		}
		for in, want := range cases {
			got, err := handlers.protoKeyAlgorithmToX509(in)
			require.NoError(t, err, in.String())
			assert.Equal(t, want, got, in.String())
		}
	})

	t.Run("an undefined algorithm is a typed error", func(t *testing.T) {
		_, err := handlers.protoKeyAlgorithmToX509(platformv1.KeyAlgorithm(999))

		var invalid ErrInvalidKeyAlgorithm
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "999", invalid.Algorithm)
	})
}
