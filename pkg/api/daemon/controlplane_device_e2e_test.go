// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// TestControlPlaneAsDevice_EndToEnd is the #472 proof in code: the control
// plane registers itself in its own registry from its own TPM, the
// collector resolves its own loopback endpoint, dials its OWN quote route
// through the real caller-admission gate, and the verdict lands in both the
// verifier's sink and the report cache — the same path a node's verdict
// takes, with no self-report shortcut and no admission bypass.
func TestControlPlaneAsDevice_EndToEnd(t *testing.T) {
	f := newQuoteFixture(t)
	pki := newControlPlanePKI(t, "cp.example.internal")

	// 1. The control plane registers itself. The device record comes out of
	// its own TPM through pkg/device's one registration implementation.
	tpm := newControlPlaneTPMStub(t, f.key, f.ca.issueAK(t, &f.key.PublicKey, true))
	registrar, err := devicepkg.NewControlPlaneRegistrar(devicepkg.ControlPlaneRegistrarConfig{
		TPM:     tpm,
		Devices: f.devices,
		Model:   "test-model",
		Serial:  "SN-CP",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	result, err := registrar.Register(context.Background())
	require.NoError(t, err)
	require.True(t, result.Created)
	selfID := strconv.FormatUint(result.Device.ID, 10)

	stored, err := f.devices.Get(context.Background(), result.Device.ID)
	require.NoError(t, err)
	assert.Equal(t, "cp.example.internal", stored.Hostname)
	assert.NotEmpty(t, stored.AttestCert, "the control plane's own IAK certificate is the quote anchor")
	assert.NotEmpty(t, stored.AttestPub)

	// The collector's device list picks it up like any other device.
	assert.Contains(t, attestableSerials(t, f.devices), "SN-CP")

	// 2. The control plane's own listener, gated by the REAL caller policy.
	// The collector presents the control plane's webservice identity; the
	// policy's reporting-server set is the one derived from a
	// self-referential ACME directory.
	policy, err := calleradmission.New(calleradmission.Config{
		Strategy:         calleradmission.StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          []*x509.Certificate{pki.root},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	var admitted []string
	quote := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/attestation/host", r.URL.Path)
		id, ok := restattestation.AdmittedCaller(r.Context())
		require.True(t, ok, "the handler runs only for an admitted machine caller")
		admitted = append(admitted, id)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req struct {
			Nonce string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal(body, &req))
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(nodeEnvelope(t, signedEvidence(t, f.key, boundTo(t, r.TLS, nonce), goldenPCRs(), goldenPCRs())))
		require.NoError(t, err)
	})
	gate := restattestation.NewCallerGate(
		logging.NewLogger(slog.LevelError, io.Discard), policy,
		response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil))
	// An operator with no client certificate must never reach quote
	// production in this test: the machine path is what is under test.
	operatorRefused := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	cp := httptest.NewUnstartedServer(gate.Wrap(quote, func(http.Handler) http.Handler {
		return operatorRefused
	}))
	cp.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pki.pool,
		MinVersion:   tls.VersionTLS12,
	}
	cp.StartTLS()
	t.Cleanup(cp.Close)

	// 3. The collector resolves the control plane's own endpoint. Nothing
	// is fed in by hand: the resolver is the production one, configured
	// with the self endpoint the serve path builds.
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(cp.URL, "https://"))
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	addresses, err := reporting.NewDeviceAddressResolver(reporting.DeviceAddressResolverConfig{
		Devices: &controlPlaneRecords{devices: f.devices},
		Port:    9443,
		Self: &reporting.SelfEndpoint{
			DeviceID:   selfID,
			Host:       host,
			Port:       port,
			ServerName: "cp.example.internal",
		},
	})
	require.NoError(t, err)
	endpoints, err := addresses.Endpoints(context.Background(), selfID)
	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	assert.Equal(t, reporting.SourceControlPlaneLoopback, endpoints[0].Source)

	source, err := reporting.NewNodeQuoteSource(reporting.NodeQuoteSourceConfig{
		Addresses: addresses,
		TLS: func(context.Context, reporting.Endpoint) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{pki.client},
				RootCAs:      pki.pool,
				MinVersion:   tls.VersionTLS12,
			}, nil
		},
	})
	require.NoError(t, err)

	verifier, err := DeviceQuoteVerifierForReporting(f.devices, f.profiles, f.trust, f.sink, nil)
	require.NoError(t, err)
	cache := reporting.NewCache(time.Hour)
	collector, err := reporting.NewCollector(reporting.Config{
		Source: source, Verifier: verifier, Cache: cache,
	})
	require.NoError(t, err)

	_, ok := cache.Report(selfID)
	require.False(t, ok, "reading the cache never produces a quote")

	// 4. Collect. The verdict must reach the cache and the sink.
	collector.Collect(context.Background(), selfID)

	assert.Equal(t, []string{"cp.example.internal"}, admitted,
		"the control plane was admitted to its own quote route by the same policy that admits it on a node")

	view, ok := cache.View(selfID)
	require.True(t, ok, "the control plane's own report is in the store")
	assert.True(t, view.Verified, view.Message)
	assert.True(t, view.AKCertificateVerified)
	assert.True(t, view.SignatureValid)
	assert.True(t, view.NonceValid)
	assert.True(t, view.PCRsValid)
	assert.True(t, view.Fresh)
	assert.Equal(t, "SN-CP", view.Serial)

	dv := f.sink.last(t)
	assert.True(t, dv.Passed, "the control plane's verdict reached the sink")
	assert.Equal(t, result.Device.ID, dv.DeviceID)
}

// TestControlPlaneAsDevice_RefusedCallerIsACollectionFailureNotAVerdict
// proves the admission check on the control plane's own listener is real:
// a collector whose certificate the policy refuses gets a 403, and a 403 is
// absence of evidence, never a failed attestation.
func TestControlPlaneAsDevice_RefusedCallerIsACollectionFailureNotAVerdict(t *testing.T) {
	f := newQuoteFixture(t)
	pki := newControlPlanePKI(t, "cp.example.internal")
	tpm := newControlPlaneTPMStub(t, f.key, f.ca.issueAK(t, &f.key.PublicKey, true))
	registrar, err := devicepkg.NewControlPlaneRegistrar(devicepkg.ControlPlaneRegistrarConfig{
		TPM: tpm, Devices: f.devices, Model: "test-model", Serial: "SN-CP",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	result, err := registrar.Register(context.Background())
	require.NoError(t, err)
	selfID := strconv.FormatUint(result.Device.ID, 10)

	// The policy names a different reporting server, so this control
	// plane's own identity is not on its list. The auditor is what proves
	// the refusal actually happened rather than the dial failing for some
	// unrelated reason and the assertions passing vacuously.
	audit := &recordingAdmissionAuditor{}
	policy, err := calleradmission.New(calleradmission.Config{
		Strategy:         calleradmission.StrategyReportingServers,
		ReportingServers: []string{"some-other-reporting-server.example.internal"},
		Anchors:          []*x509.Certificate{pki.root},
		Auditor:          audit,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	reached := 0
	gate := restattestation.NewCallerGate(
		logging.NewLogger(slog.LevelError, io.Discard), policy, response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil))
	cp := httptest.NewUnstartedServer(gate.Wrap(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }), nil))
	cp.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pki.pool,
		MinVersion:   tls.VersionTLS12,
	}
	cp.StartTLS()
	t.Cleanup(cp.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(cp.URL, "https://"))
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	addresses, err := reporting.NewDeviceAddressResolver(reporting.DeviceAddressResolverConfig{
		Devices: &controlPlaneRecords{devices: f.devices},
		Port:    9443,
		Self:    &reporting.SelfEndpoint{DeviceID: selfID, Host: host, Port: port, ServerName: "cp.example.internal"},
	})
	require.NoError(t, err)
	source, err := reporting.NewNodeQuoteSource(reporting.NodeQuoteSourceConfig{
		Addresses: addresses,
		TLS: func(context.Context, reporting.Endpoint) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{pki.client},
				RootCAs:      pki.pool,
				MinVersion:   tls.VersionTLS12,
			}, nil
		},
	})
	require.NoError(t, err)
	verifier, err := DeviceQuoteVerifierForReporting(f.devices, f.profiles, f.trust, f.sink, nil)
	require.NoError(t, err)
	cache := reporting.NewCache(time.Hour)
	collector, err := reporting.NewCollector(reporting.Config{Source: source, Verifier: verifier, Cache: cache})
	require.NoError(t, err)

	collector.Collect(context.Background(), selfID)

	require.Len(t, audit.decisions, 1, "the caller gate evaluated the collector")
	assert.False(t, audit.decisions[0].Admitted)
	assert.Equal(t, calleradmission.ReasonNotListed, audit.decisions[0].Reason)
	assert.Zero(t, reached, "a refused caller never reaches quote production")
	_, ok := cache.View(selfID)
	assert.False(t, ok, "a refusal is absence of evidence, never a synthesised failed verdict")
	assert.Empty(t, f.sink.verdicts, "no verdict is recorded for a collection that failed")
}

// TestControlPlaneAsDevice_LegacyIAKCertificateDoesNotQuarantineTheControlPlane
// is the safety property the #472 follow-up exists for, proved end to end
// rather than argued.
//
// The live fleet's IAK certificates were issued by a pre-0.9.4 CA and carry
// no tcg-cap-verifiedTPMRestricted. The device quote verifier treats a
// MISSING attestation certificate as an ABSENT check, but a PRESENT one that
// fails verification as a CRYPTOGRAPHIC failure — and
// attestation/service.RecordDeviceVerdict dispatches a cryptographic verdict
// to the quarantine observers. So recording such a certificate would have the
// control plane quarantine itself on its first self-collection.
//
// Registration drops it, and this test collects a real quote from the control
// plane's own listener and asserts the verdict that comes back is a failure
// that is NOT cryptographic: denied service, nothing quarantined.
func TestControlPlaneAsDevice_LegacyIAKCertificateDoesNotQuarantineTheControlPlane(t *testing.T) {
	f := newQuoteFixture(t)
	pki := newControlPlanePKI(t, "cp.example.internal")

	// The control plane's TPM holds the certificate the fleet actually has:
	// issued by its own CA, without the Restricted policy.
	tpm := newControlPlaneTPMStub(t, f.key, f.ca.issueAK(t, &f.key.PublicKey, false))
	registrar, err := devicepkg.NewControlPlaneRegistrar(devicepkg.ControlPlaneRegistrarConfig{
		TPM: tpm, Devices: f.devices, Model: "test-model", Serial: "SN-CP",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	result, err := registrar.Register(context.Background())
	require.NoError(t, err)
	require.Empty(t, result.Device.AttestCert, "the non-compliant certificate is not recorded")
	require.NotEmpty(t, result.AttestCertWarning)
	selfID := strconv.FormatUint(result.Device.ID, 10)

	policy, err := calleradmission.New(calleradmission.Config{
		Strategy:         calleradmission.StrategyReportingServers,
		ReportingServers: []string{"cp.example.internal"},
		Anchors:          []*x509.Certificate{pki.root},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	gate := restattestation.NewCallerGate(
		logging.NewLogger(slog.LevelError, io.Discard), policy,
		response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil))
	cp := httptest.NewUnstartedServer(gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req struct {
			Nonce string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal(body, &req))
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(nodeEnvelope(t, signedEvidence(t, f.key, boundTo(t, r.TLS, nonce), goldenPCRs(), goldenPCRs())))
		require.NoError(t, err)
	}), nil))
	cp.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pki.pool,
		MinVersion:   tls.VersionTLS12,
	}
	cp.StartTLS()
	t.Cleanup(cp.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(cp.URL, "https://"))
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	addresses, err := reporting.NewDeviceAddressResolver(reporting.DeviceAddressResolverConfig{
		Devices: &controlPlaneRecords{devices: f.devices},
		Port:    9443,
		Self:    &reporting.SelfEndpoint{DeviceID: selfID, Host: host, Port: port, ServerName: "cp.example.internal"},
	})
	require.NoError(t, err)
	source, err := reporting.NewNodeQuoteSource(reporting.NodeQuoteSourceConfig{
		Addresses: addresses,
		TLS: func(context.Context, reporting.Endpoint) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{pki.client},
				RootCAs:      pki.pool,
				MinVersion:   tls.VersionTLS12,
			}, nil
		},
	})
	require.NoError(t, err)
	verifier, err := DeviceQuoteVerifierForReporting(f.devices, f.profiles, f.trust, f.sink, nil)
	require.NoError(t, err)
	cache := reporting.NewCache(time.Hour)
	collector, err := reporting.NewCollector(reporting.Config{Source: source, Verifier: verifier, Cache: cache})
	require.NoError(t, err)

	collector.Collect(context.Background(), selfID)

	view, ok := cache.View(selfID)
	require.True(t, ok, "the control plane was collected")
	assert.False(t, view.Verified, "without a verifiable anchor it cannot be attested")
	assert.False(t, view.AKCertificateVerified)
	assert.False(t, view.CryptographicFailure,
		"THE property: no anchor is absence of evidence, not a failed attestation")

	dv := f.sink.last(t)
	assert.False(t, dv.Passed)
	assert.False(t, dv.Cryptographic,
		"a cryptographic verdict is what attestation/service dispatches to the quarantine observers")
}

// recordingAdmissionAuditor captures every admission decision so a refusal
// can be told apart from a dial that never reached the policy.
type recordingAdmissionAuditor struct {
	decisions []calleradmission.Decision
}

func (a *recordingAdmissionAuditor) RecordAdmission(_ context.Context, d calleradmission.Decision) error {
	a.decisions = append(a.decisions, d)
	return nil
}

// controlPlaneRecords adapts the fixture device service to the address
// resolver's read, the way the serve path's deviceRecordsAdapter does.
type controlPlaneRecords struct {
	devices *spMockDeviceService
}

func (c *controlPlaneRecords) AddressRecord(ctx context.Context, deviceID string) (*reporting.DeviceAddressRecord, error) {
	id, err := strconv.ParseUint(deviceID, 10, 64)
	if err != nil {
		return nil, err
	}
	dev, err := c.devices.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &reporting.DeviceAddressRecord{Hostname: dev.Hostname, HeartbeatAddr: dev.LastHeartbeatAddr}, nil
}

// attestableSerials lists the serials of every device carrying attestation
// material, which is what the collector's device list selects.
func attestableSerials(t *testing.T, devices *spMockDeviceService) []string {
	t.Helper()
	page, err := devices.Page(context.Background(), datastore.PageQuery{Page: 1, PageSize: 100})
	require.NoError(t, err)
	var out []string
	for _, dev := range page.Entities {
		if dev.AttestCert != "" || dev.AttestPub != "" {
			out = append(out, dev.Serial)
		}
	}
	return out
}

// controlPlaneTPMStub answers the reads devicepkg.ControlPlaneRegistrar
// makes, standing in for the control plane's own TPM.
type controlPlaneTPMStub struct {
	ek       *x509.Certificate
	iak      *x509.Certificate
	idevid   *x509.Certificate
	iakAttrs *xkmssdk.KeyAttributes
	sgnAttrs *xkmssdk.KeyAttributes
	eventLog []byte
}

func newControlPlaneTPMStub(t *testing.T, iakKey *rsa.PrivateKey, attestCertPEM string) *controlPlaneTPMStub {
	t.Helper()
	block, _ := pem.Decode([]byte(attestCertPEM))
	require.NotNil(t, block, "the fixture CA issued a PEM attestation certificate")
	iak, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return &controlPlaneTPMStub{
		ek:       controlPlaneSelfSigned(t, "ek-cp"),
		iak:      iak,
		idevid:   controlPlaneSelfSigned(t, "cp.example.internal"),
		iakAttrs: rsaKeyAttributes(t, &iakKey.PublicKey, true),
		sgnAttrs: rsaKeyAttributes(t, &iakKey.PublicKey, false),
		eventLog: []byte("binary_bios_measurements"),
	}
}

func (s *controlPlaneTPMStub) EKCertificate() (*x509.Certificate, error)     { return s.ek, nil }
func (s *controlPlaneTPMStub) IAKCertificate() (*x509.Certificate, error)    { return s.iak, nil }
func (s *controlPlaneTPMStub) IDevIDCertificate() (*x509.Certificate, error) { return s.idevid, nil }
func (s *controlPlaneTPMStub) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return s.iakAttrs, nil
}
func (s *controlPlaneTPMStub) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	return s.sgnAttrs, nil
}
func (s *controlPlaneTPMStub) EventLog() ([]byte, error) { return s.eventLog, nil }

// rsaKeyAttributes wraps an RSA public key as the TPMT_PUBLIC public area
// the TPM returns from ReadPublic on the IAK's persistent handle.
func rsaKeyAttributes(t *testing.T, pub *rsa.PublicKey, restricted bool) *xkmssdk.KeyAttributes {
	t.Helper()
	area := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          restricted,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme:  tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			KeyBits:  2048,
			Exponent: uint32(pub.E), // #nosec G115 -- an RSA exponent is small
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: pub.N.Bytes()}),
	}
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{BPublic: tpm2.New2B(area)},
	}
}

// controlPlanePKI issues the control plane's own root, the webservice
// server certificate its listener presents, and the client certificate its
// collector presents. Every validity window is relative to the clock: a
// literal date in a fixture expires silently (#506).
type controlPlanePKI struct {
	root   *x509.Certificate
	pool   *x509.CertPool
	server tls.Certificate
	client tls.Certificate
}

func newControlPlanePKI(t *testing.T, name string) *controlPlanePKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "root-ca." + name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	issue := func(cn string, ekus []x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			DNSNames:     []string{cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  ekus,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return &controlPlanePKI{
		root:   root,
		pool:   pool,
		server: issue(name, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
		client: issue(name, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}),
	}
}

func controlPlaneSelfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
