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

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

func selfSignedCA(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func writeCallerBundle(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	f, err := os.Create(path)
	require.NoError(t, err)
	for _, c := range certs {
		require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	require.NoError(t, f.Close())
	return path
}

type noopAuditor struct{ n int }

func (a *noopAuditor) RecordAdmission(context.Context, calleradmission.Decision) error {
	a.n++
	return nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestBuildCallerPolicy_DerivesReportingServerFromACMEDirectory(t *testing.T) {
	root := selfSignedCA(t, "root-ca.cp.example.io", true)
	p, err := buildCallerPolicy(callerPolicyInputs{
		ACMEDirectory:  "https://CP.Example.Internal:9443/api/v1/acme/directory",
		PlatformAnchor: fixedAnchor(t, root),
		Auditor:        &noopAuditor{},
		Logger:         quietLogger(),
	})
	require.NoError(t, err)
	desc := p.Describe()
	assert.Equal(t, calleradmission.StrategyReportingServers, desc.Strategy)
	assert.Equal(t, []string{"cp.example.internal"}, desc.Identities)
	assert.Equal(t, callerIdentitiesDerived, desc.IdentitiesSource)
	assert.Equal(t, callerAnchorsPlatform, desc.AnchorSource)
	assert.True(t, desc.AnchorsConfigured)
	assert.False(t, desc.AdmitsNobody)
	assert.Len(t, p.Anchors(), 1)
}

func TestBuildCallerPolicy_ConfiguredListReplacesTheDerivedOne(t *testing.T) {
	p, err := buildCallerPolicy(callerPolicyInputs{
		Callers:       &config.CallerAdmissionConfig{ReportingServers: []string{"reporting-01.example.internal"}},
		ACMEDirectory: "https://cp.example.internal:9443/api/v1/acme/directory",
		Logger:        quietLogger(),
	})
	require.NoError(t, err)
	desc := p.Describe()
	assert.Equal(t, []string{"reporting-01.example.internal"}, desc.Identities, "no union with the derived host")
	assert.Equal(t, callerIdentitiesConfigured, desc.IdentitiesSource)
	assert.True(t, desc.AdmitsNobody, "no anchors at all: nobody is admitted whatever the list says")
}

func TestBuildCallerPolicy_AnchorPrecedence(t *testing.T) {
	configured := selfSignedCA(t, "configured-ca", true)
	heartbeat := selfSignedCA(t, "heartbeat-ca", true)
	idevid := selfSignedCA(t, "idevid-root", true)
	configuredPath := writeCallerBundle(t, configured)
	heartbeatPath := writeCallerBundle(t, heartbeat)
	anchor := fixedAnchor(t, idevid)

	p, err := buildCallerPolicy(callerPolicyInputs{
		Callers:         &config.CallerAdmissionConfig{CAFile: configuredPath, ReportingServers: []string{"x"}},
		HeartbeatCAFile: heartbeatPath, PlatformAnchor: anchor, Logger: quietLogger(),
	})
	require.NoError(t, err)
	assert.Equal(t, callerAnchorsCAFile, p.Describe().AnchorSource)
	assert.Equal(t, "configured-ca", p.Anchors()[0].Subject.CommonName)

	p, err = buildCallerPolicy(callerPolicyInputs{
		Callers:         &config.CallerAdmissionConfig{ReportingServers: []string{"x"}},
		HeartbeatCAFile: heartbeatPath, PlatformAnchor: anchor, Logger: quietLogger(),
	})
	require.NoError(t, err)
	assert.Equal(t, callerAnchorsHeartbeatCA, p.Describe().AnchorSource)
	assert.Equal(t, "heartbeat-ca", p.Anchors()[0].Subject.CommonName)

	p, err = buildCallerPolicy(callerPolicyInputs{
		Callers: &config.CallerAdmissionConfig{ReportingServers: []string{"x"}}, PlatformAnchor: anchor, Logger: quietLogger(),
	})
	require.NoError(t, err)
	assert.Equal(t, callerAnchorsPlatform, p.Describe().AnchorSource)

	p, err = buildCallerPolicy(callerPolicyInputs{
		Callers:        &config.CallerAdmissionConfig{ReportingServers: []string{"x"}},
		PlatformAnchor: failingAnchor(t, errors.New("no idevid")), Logger: quietLogger(),
	})
	require.NoError(t, err)
	assert.Empty(t, p.Describe().AnchorSource)
	assert.True(t, p.Describe().AdmitsNobody)
}

func TestBuildCallerPolicy_ConfiguredBundleMustBeUsable(t *testing.T) {
	_, err := buildCallerPolicy(callerPolicyInputs{
		Callers: &config.CallerAdmissionConfig{CAFile: filepath.Join(t.TempDir(), "missing.pem")}, Logger: quietLogger(),
	})
	var unreadable ErrCallerAnchorsUnreadable
	require.ErrorAs(t, err, &unreadable)
	assert.Contains(t, unreadable.Error(), "missing.pem")

	leafOnly := writeCallerBundle(t, selfSignedCA(t, "not-a-ca", false))
	_, err = buildCallerPolicy(callerPolicyInputs{
		Callers: &config.CallerAdmissionConfig{CAFile: leafOnly}, Logger: quietLogger(),
	})
	require.ErrorAs(t, err, &unreadable)
	var empty ErrCallerAnchorsEmpty
	assert.ErrorAs(t, err, &empty)

	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600))
	_, err = buildCallerPolicy(callerPolicyInputs{HeartbeatCAFile: garbage, Logger: quietLogger()})
	require.ErrorAs(t, err, &unreadable)

	_, err = buildCallerPolicy(callerPolicyInputs{
		Callers: &config.CallerAdmissionConfig{Strategy: "nobody-knows"}, Logger: quietLogger(),
	})
	require.Error(t, err)
}

func TestBuildCallerPolicy_AnyAttestedWithoutEvidenceAdmitsNobody(t *testing.T) {
	root := selfSignedCA(t, "root", true)
	p, err := buildCallerPolicy(callerPolicyInputs{
		Callers:        &config.CallerAdmissionConfig{Strategy: config.CallerStrategyAnyAttested},
		PlatformAnchor: fixedAnchor(t, root),
		Logger:         quietLogger(),
	})
	require.NoError(t, err)
	assert.True(t, p.Describe().AdmitsNobody)
}

func TestACMEDirectoryHost(t *testing.T) {
	assert.Equal(t, "cp.example.internal", acmeDirectoryHost("https://CP.example.internal:9443/api/v1/acme/directory"))
	assert.Equal(t, "", acmeDirectoryHost(""))
	assert.Equal(t, "", acmeDirectoryHost("://bad"))
	assert.Equal(t, "192.168.1.1", acmeDirectoryHost("https://192.168.1.1:9443/dir"))
}

func TestInitCallerPolicy_NilAppIsNil(t *testing.T) {
	assert.Nil(t, initCallerPolicy(quietLogger(), nil, nil))
}

// fixedAnchor is a platform anchor holding root.
func fixedAnchor(t *testing.T, root *x509.Certificate) *trust.Anchor {
	t.Helper()
	anchor, err := trust.NewAnchor(trust.AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
		return []*x509.Certificate{root}, nil
	}))
	require.NoError(t, err)
	return anchor
}

// failingAnchor is the platform anchor of a node that has not enrolled.
func failingAnchor(t *testing.T, cause error) *trust.Anchor {
	t.Helper()
	anchor, err := trust.NewAnchor(trust.AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
		return nil, cause
	}))
	require.NoError(t, err)
	return anchor
}
