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

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

func webService(name, cn string, tlsPort, port int, sans ...string) *v1.Config {
	ws := &v1.Config{
		Name:    name,
		Port:    port,
		TLSPort: tlsPort,
		Certificate: common.Identity{
			Subject: trustedca.CASubject{CommonName: cn},
		},
	}
	if len(sans) > 0 {
		ws.Certificate.SANS = &trustedca.CASubjectAlternativeNames{DNS: sans}
	}
	return ws
}

func TestResolveProductAttributes_ConfigWinsOverDiscovery(t *testing.T) {
	model, serial := resolveProductAttributes(
		&xkmssdk.IDevIDConfig{Model: " configured-model ", Serial: "configured-serial"},
		"smbios-model", "smbios-serial")
	assert.Equal(t, "configured-model", model)
	assert.Equal(t, "configured-serial", serial)
}

func TestResolveProductAttributes_FallsBackToDiscovery(t *testing.T) {
	model, serial := resolveProductAttributes(&xkmssdk.IDevIDConfig{}, " smbios-model ", "smbios-serial")
	assert.Equal(t, "smbios-model", model)
	assert.Equal(t, "smbios-serial", serial)

	model, serial = resolveProductAttributes(nil, "smbios-model", "smbios-serial")
	assert.Equal(t, "smbios-model", model)
	assert.Equal(t, "smbios-serial", serial)

	model, serial = resolveProductAttributes(nil, "", "")
	assert.Equal(t, "", model)
	assert.Equal(t, "", serial, "a machine SMBIOS cannot name is refused later, not guessed here")
}

func TestControlPlaneQuoteEndpoint_UsesTheCollectorIdentityListener(t *testing.T) {
	a := &app.App{WebServices: []*v1.Config{
		webService("public", "cp.example.com", 8443, 8080),
		webService("internal", "cp.example.internal", 9443, 9080),
	}}
	host, port, serverName := controlPlaneQuoteEndpoint(a, &config.CollectorConfig{Identity: "internal"})
	assert.Equal(t, reporting.DefaultSelfHost, host)
	assert.Equal(t, 9443, port)
	assert.Equal(t, "cp.example.internal", serverName,
		"the collector calls the listener whose identity it presents")
}

func TestControlPlaneQuoteEndpoint_FallsBackToThePrimaryWebService(t *testing.T) {
	a := &app.App{WebServices: []*v1.Config{
		webService("public", "cp.example.com", 8443, 8080),
	}}
	_, port, serverName := controlPlaneQuoteEndpoint(a, nil)
	assert.Equal(t, 8443, port)
	assert.Equal(t, "cp.example.com", serverName)
}

func TestControlPlaneQuoteEndpoint_PortAndNamePrecedence(t *testing.T) {
	// No TLS port: the plain port is what the listener answers on.
	a := &app.App{WebServices: []*v1.Config{webService("public", "cp.example.com", 0, 8080)}}
	_, port, _ := controlPlaneQuoteEndpoint(a, nil)
	assert.Equal(t, 8080, port)

	// No ports at all: the collector's configured node port.
	a = &app.App{WebServices: []*v1.Config{webService("public", "cp.example.com", 0, 0)}}
	_, port, _ = controlPlaneQuoteEndpoint(a, &config.CollectorConfig{Port: 7443})
	assert.Equal(t, 7443, port)

	// No webservice at all: the node port and no name; the address resolver
	// then falls back to the device FQDN, and refuses if there is not one.
	_, port, serverName := controlPlaneQuoteEndpoint(&app.App{}, nil)
	assert.Equal(t, config.DefaultReportingPort, port)
	assert.Equal(t, "", serverName)
}

func TestWebServiceCertificateName_FallsBackToTheFirstDNSSAN(t *testing.T) {
	assert.Equal(t, "", webServiceCertificateName(nil))
	assert.Equal(t, "", webServiceCertificateName(webService("public", "", 8443, 0)))
	assert.Equal(t, "cp.example.internal",
		webServiceCertificateName(webService("public", "", 8443, 0, " ", "cp.example.internal")))
	assert.Equal(t, "cp.example.com",
		webServiceCertificateName(webService("public", "cp.example.com", 8443, 0, "other.example.com")))
}

func TestInitControlPlaneDevice_NotAControlPlaneOrNothingToWriteTo(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, initControlPlaneDevice(ctx, quietLogger(), nil, nil))

	a := &app.App{}
	cfg := &daemon.Config{}
	assert.Nil(t, initControlPlaneDevice(ctx, quietLogger(), a, cfg),
		"a node that runs no collector registers no self record")

	a.AttestationConfig.Reporting = &config.ReportingConfig{Enabled: true}
	assert.Nil(t, initControlPlaneDevice(ctx, quietLogger(), a, cfg), "no device registry")

	cfg.DeviceService = &fakeDevices{}
	assert.Nil(t, initControlPlaneDevice(ctx, quietLogger(), a, cfg), "no TPM")
}

// TestControlPlaneAdmitsItsOwnCollector is the measurement the #472 design
// asked for rather than assumed: the control plane's caller-admission
// policy, compiled exactly as the serve path compiles it, admits the
// collector's own webservice identity on the control plane's own listener.
// It is the same policy that admits the control plane on every node — no
// bypass, no loopback exemption.
func TestControlPlaneAdmitsItsOwnCollector(t *testing.T) {
	root, rootKey := controlPlaneTestRoot(t)
	// The identity the collector presents when it dials: the internal
	// webservice's certificate, issued by this control plane's own CA.
	collectorCert := issueCollectorIdentity(t, root, rootKey, "cp.example.internal")

	policy, err := buildCallerPolicy(callerPolicyInputs{
		Logger: quietLogger(),
		// Self-referential ACME: the control plane's client directory points
		// at its own internal webservice, so the derived reporting-server
		// identity is its own name.
		ACMEDirectory:    "https://cp.example.internal:9443/acme/directory",
		IDevIDIssuerRoot: func() (*x509.Certificate, error) { return root, nil },
	})
	require.NoError(t, err)

	desc := policy.Describe()
	assert.Equal(t, calleradmission.StrategyReportingServers, desc.Strategy)
	assert.Equal(t, []string{"cp.example.internal"}, desc.Identities)
	assert.False(t, desc.AdmitsNobody)

	d := policy.Evaluate(context.Background(), &calleradmission.Peer{
		Leaf:       collectorCert,
		RemoteAddr: "127.0.0.1:51234",
	})
	assert.True(t, d.Admitted, d.Detail)
	assert.Equal(t, calleradmission.ReasonAdmitted, d.Reason)
	assert.Equal(t, "cp.example.internal", d.Identity)
}

// TestControlPlaneRefusesAnImpostorOnItsOwnListener is the other half: a
// certificate from another issuer, and one carrying another name, are both
// refused on the loopback address exactly as they would be from the network.
func TestControlPlaneRefusesAnImpostorOnItsOwnListener(t *testing.T) {
	root, rootKey := controlPlaneTestRoot(t)
	other, otherKey := controlPlaneTestRoot(t)

	policy, err := buildCallerPolicy(callerPolicyInputs{
		Logger:           quietLogger(),
		ACMEDirectory:    "https://cp.example.internal:9443/acme/directory",
		IDevIDIssuerRoot: func() (*x509.Certificate, error) { return root, nil },
	})
	require.NoError(t, err)

	wrongIssuer := issueCollectorIdentity(t, other, otherKey, "cp.example.internal")
	d := policy.Evaluate(context.Background(), &calleradmission.Peer{
		Leaf: wrongIssuer, RemoteAddr: "127.0.0.1:51235",
	})
	assert.False(t, d.Admitted)
	assert.Equal(t, calleradmission.ReasonUntrustedIssuer, d.Reason)

	wrongName := issueCollectorIdentity(t, root, rootKey, "worker-01.example.internal")
	d = policy.Evaluate(context.Background(), &calleradmission.Peer{
		Leaf: wrongName, RemoteAddr: "127.0.0.1:51236",
	})
	assert.False(t, d.Admitted)
	assert.Equal(t, calleradmission.ReasonNotListed, d.Reason)
}

// controlPlaneTestRoot issues a throwaway root. Its validity is relative to
// the clock: a fixture with a literal date expires silently (#506).
func controlPlaneTestRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "root-ca.cp.example.internal"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func issueCollectorIdentity(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// wiringTPM answers the reads the control-plane registrar makes. It is the
// narrow ControlPlaneTPM surface, not the whole platform TPM.
type wiringTPM struct {
	iakAttrs *xkmssdk.KeyAttributes
	iakErr   error
	idevid   *x509.Certificate
}

func (w *wiringTPM) EKCertificate() (*x509.Certificate, error) {
	return nil, errors.New("no manufacturer EK certificate")
}
func (w *wiringTPM) IAKCertificate() (*x509.Certificate, error)    { return w.idevid, nil }
func (w *wiringTPM) IDevIDCertificate() (*x509.Certificate, error) { return w.idevid, nil }
func (w *wiringTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return w.iakAttrs, w.iakErr
}
func (w *wiringTPM) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) { return w.iakAttrs, nil }
func (w *wiringTPM) EventLog() ([]byte, error)                         { return []byte("log"), nil }

func newWiringTPM(t *testing.T) *wiringTPM {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	point, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	area := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, Restricted: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: point[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: point[33:65]},
		}),
	}
	root, rootKey := controlPlaneTestRoot(t)
	return &wiringTPM{
		iakAttrs: &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{BPublic: tpm2.New2B(area)},
		},
		idevid: issueCollectorIdentity(t, root, rootKey, "cp.example.internal"),
	}
}

func TestRegisterControlPlaneDevice_WritesTheRecordAndTheSelfEndpoint(t *testing.T) {
	a := &app.App{
		WebServices: []*v1.Config{
			webService("public", "cp.example.com", 8443, 8080),
			webService("internal", "cp.example.internal", 9443, 9080),
		},
	}
	a.AttestationConfig.Reporting = &config.ReportingConfig{
		Enabled:   true,
		Collector: &config.CollectorConfig{Identity: "internal"},
	}
	a.TPMConfig.IDevID = &xkmssdk.IDevIDConfig{Model: "SuperMicro X10SDV", Serial: "SN-CP-1"}
	devices := &fakeDevices{byID: map[uint64]*entities.Device{}}
	cfg := &daemon.Config{DeviceService: devices}

	self := registerControlPlaneDevice(context.Background(), quietLogger(), a, cfg, newWiringTPM(t))
	require.NotNil(t, self)
	assert.Equal(t, "SN-CP-1", self.Serial)
	assert.Equal(t, "cp.example.internal", self.Hostname)
	assert.Equal(t, self.DeviceID, self.Endpoint.DeviceID)
	assert.Equal(t, reporting.DefaultSelfHost, self.Endpoint.Host)
	assert.Equal(t, 9443, self.Endpoint.Port)
	assert.Equal(t, "cp.example.internal", self.Endpoint.ServerName)
}

func TestRegisterControlPlaneDevice_TPMFailureIsNotFatal(t *testing.T) {
	a := &app.App{}
	a.AttestationConfig.Reporting = &config.ReportingConfig{Enabled: true}
	a.TPMConfig.IDevID = &xkmssdk.IDevIDConfig{Serial: "SN-CP-1"}
	devices := &fakeDevices{byID: map[uint64]*entities.Device{}}
	cfg := &daemon.Config{DeviceService: devices}

	tpm := newWiringTPM(t)
	tpm.iakErr = errors.New("handle 0x81010002 not found")
	assert.Nil(t, registerControlPlaneDevice(context.Background(), quietLogger(), a, cfg, tpm),
		"the daemon keeps serving the fleet when its own record cannot be written")
}

func TestControlPlaneWebService_MatchesTheSingularWebService(t *testing.T) {
	ws := webService("internal", "cp.example.internal", 9443, 9080)
	a := &app.App{WebServiceConfig: ws}
	assert.Same(t, ws, controlPlaneWebService(a, &config.CollectorConfig{Identity: "internal"}))

	// A name that matches nothing falls back to the primary webservice.
	assert.Same(t, ws, controlPlaneWebService(a, &config.CollectorConfig{Identity: "nowhere"}))
}
