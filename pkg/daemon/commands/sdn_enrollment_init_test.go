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
	"log/slog"
	"math/big"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wiringStubEngine is a minimal PolicyEngine for the production-wiring
// tests: it records the applied policy and port states so the assertions
// can prove what the hook committed.
type wiringStubEngine struct {
	appliedPolicies map[string]*policy.PortPolicy
	portStates      map[string]policy.PortState
}

func newWiringStubEngine() *wiringStubEngine {
	return &wiringStubEngine{
		appliedPolicies: make(map[string]*policy.PortPolicy),
		portStates:      make(map[string]policy.PortState),
	}
}

func (e *wiringStubEngine) SetPortState(portID string, state policy.PortState) error {
	e.portStates[portID] = state
	return nil
}

func (e *wiringStubEngine) GetPortState(portID string) (policy.PortState, error) {
	state, ok := e.portStates[portID]
	if !ok {
		return policy.PortStateProvisioning, &policy.MessageError{Msg: "port state not found"}
	}
	return state, nil
}

func (e *wiringStubEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	return nil, &policy.MessageError{Msg: "not tracked by stub"}
}

func (e *wiringStubEngine) ApplyPolicy(portID string, p *policy.PortPolicy) error {
	e.appliedPolicies[portID] = p
	// The real engine leaves the port authorized after ApplyPolicy; the
	// hook then overrides to quarantined on a zone-mismatch plan.
	e.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (e *wiringStubEngine) RemovePolicy(portID string) error {
	delete(e.appliedPolicies, portID)
	return nil
}

func (e *wiringStubEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	p, ok := e.appliedPolicies[portID]
	if !ok {
		return nil, &policy.MessageError{Msg: "no policy applied"}
	}
	return p, nil
}

func (e *wiringStubEngine) SetPortVLAN(portID string, vlan uint16) error { return nil }

func (e *wiringStubEngine) GetPortVLAN(portID string) (uint16, error) {
	return 0, &policy.MessageError{Msg: "not tracked by stub"}
}

func (e *wiringStubEngine) BlockPort(portID string) error   { return nil }
func (e *wiringStubEngine) UnblockPort(portID string) error { return nil }

func (e *wiringStubEngine) GetOFPort(portID string) (int32, error) {
	return 0, &policy.MessageError{Msg: "not tracked by stub"}
}

func (e *wiringStubEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	return nil
}

func (e *wiringStubEngine) OnCertificateExpired(portID string) error { return nil }
func (e *wiringStubEngine) OnCertificateRevoked(portID string) error { return nil }
func (e *wiringStubEngine) GetMonitor() *policy.CertificateMonitor   { return nil }

// newWiringFixture builds the SDN enrollment hook through the PRODUCTION
// config constructor (newSDNEnrollmentHookConfig) over real device and
// profile services — only the MAC extractor is overridden, because the
// production default reads the host ARP table. The stored profile's trusted
// network declares zone "provisioning" with quarantine VLAN 666.
func newWiringFixture(t *testing.T) (*policy.SDNEnrollmentHook, *wiringStubEngine) {
	t.Helper()

	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.NewLogger(slog.LevelError, nil)
	ds := device.NewDatastore(storage, logger)

	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)
	devices, err := device.NewService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "wiring-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork:     {VLAN: 998},
			entities.DefaultPostEnrollmentNetwork: {VLAN: 200, Zone: "provisioning"},
			entities.DefaultFailureNetwork:        {VLAN: 666},
		},
		MatchRules: &entities.ProfileMatchRules{SerialPrefix: "SRV-"},
	}
	require.NoError(t, profiles.Save(context.Background(), profile))

	engine := newWiringStubEngine()

	cfg := newSDNEnrollmentHookConfig(engine, devices, profiles, zone.Defaults(), logger.Slog())
	// The production default extracts the MAC from the host ARP table,
	// which cannot resolve a test IP; everything else is the production
	// wiring under test.
	cfg.MACExtractor = func(string) string { return "52:54:00:12:34:56" }

	hook, err := policy.NewSDNEnrollmentHook(cfg)
	require.NoError(t, err)
	hook.RegisterPort("52:54:00:12:34:56", "port1")
	return hook, engine
}

// wiringCertWithZone issues a self-signed certificate carrying the
// OIDTPNetworkZone extension for zoneName.
func wiringCertWithZone(t *testing.T, zoneName string) *x509.Certificate {
	t.Helper()
	ext, err := quicbaasca.CreateNetworkZoneExtension(zoneName)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber:    big.NewInt(77),
		Subject:         pkix.Name{Organization: []string{"org"}, CommonName: "SRV-WIRE-01"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestSDNEnrollmentHookWiring_ZoneMismatchQuarantines proves the production
// wiring detects a certificate/profile zone mismatch: the hook built by
// newSDNEnrollmentHookConfig carries the certificate zone extractor and the
// resolved zones, so a certificate declaring zone "control-plane" against a
// profile declaring zone "provisioning" prechecks as an expected quarantine
// and activates onto the quarantine VLAN — never the post-enrollment policy.
// Without the Extractor/Zones wiring the mismatch would be silently
// accepted and this test would see a clean activation on the post-enrollment VLAN.
func TestSDNEnrollmentHookWiring_ZoneMismatchQuarantines(t *testing.T) {
	hook, engine := newWiringFixture(t)

	event := &policy.EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   wiringCertWithZone(t, "control-plane"),
		ClientIP:      "192.168.1.50",
		IsTCGCSR:      true,
		ProductSerial: "SRV-WIRE-01",
	}
	require.NoError(t, hook.OnEnrollmentComplete(event))

	plan, err := hook.PrecheckActivation("SRV-WIRE-01")
	require.NoError(t, err)
	require.True(t, plan.ExpectQuarantine(),
		"the production wiring must detect the certificate/profile zone mismatch")

	result, err := hook.ActivateDevice(plan)
	require.NoError(t, err)
	assert.Equal(t, policy.ActivationStatusQuarantined, result.Status)
	assert.Equal(t, uint16(666), result.VLAN, "the quarantine VLAN, never the trusted one")

	applied, ok := engine.appliedPolicies["port1"]
	require.True(t, ok)
	assert.Equal(t, uint16(666), applied.VLAN)
	assert.Equal(t, policy.PortStateQuarantined, engine.portStates["port1"])
}

// TestSDNEnrollmentHookWiring_MatchingZoneActivatesClean is the control for
// the mismatch test: a certificate whose zone matches the profile zone
// prechecks clean and activates onto the admitted VLAN through the same
// production config.
func TestSDNEnrollmentHookWiring_MatchingZoneActivatesClean(t *testing.T) {
	hook, engine := newWiringFixture(t)

	event := &policy.EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   wiringCertWithZone(t, "provisioning"),
		ClientIP:      "192.168.1.50",
		IsTCGCSR:      true,
		ProductSerial: "SRV-WIRE-01",
	}
	require.NoError(t, hook.OnEnrollmentComplete(event))

	plan, err := hook.PrecheckActivation("SRV-WIRE-01")
	require.NoError(t, err)
	require.False(t, plan.ExpectQuarantine())

	result, err := hook.ActivateDevice(plan)
	require.NoError(t, err)
	assert.Equal(t, policy.ActivationStatusActivated, result.Status)
	assert.Equal(t, uint16(200), result.VLAN)
	assert.Equal(t, policy.PortStateAuthorized, engine.portStates["port1"])
}
