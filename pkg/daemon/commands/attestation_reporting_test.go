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
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// fakeDevices is a minimal device.DeviceService for the wiring adapters.
type fakeDevices struct {
	byID    map[uint64]*entities.Device
	getErr  error
	pageErr error
}

func (f *fakeDevices) Save(context.Context, *entities.Device) error   { return nil }
func (f *fakeDevices) Delete(context.Context, *entities.Device) error { return nil }
func (f *fakeDevices) Update(context.Context, *entities.Device) error { return nil }
func (f *fakeDevices) Count(context.Context) (int, error)             { return len(f.byID), nil }
func (f *fakeDevices) Get(_ context.Context, id uint64) (*entities.Device, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	d, ok := f.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return d, nil
}
func (f *fakeDevices) FindBySerial(_ context.Context, serial string) (*entities.Device, error) {
	for _, d := range f.byID {
		if d.Serial == serial {
			return d, nil
		}
	}
	return nil, errors.New("not found")
}
func (f *fakeDevices) FindByHostname(_ context.Context, host string) (*entities.Device, error) {
	for _, d := range f.byID {
		if d.Hostname == host {
			return d, nil
		}
	}
	return nil, errors.New("not found")
}
func (f *fakeDevices) Page(_ context.Context, q datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	if f.pageErr != nil {
		return datastore.PageResult[*entities.Device]{}, f.pageErr
	}
	all := make([]*entities.Device, 0, len(f.byID))
	for id := uint64(1); id <= 10_000 && len(all) < len(f.byID); id++ {
		if d, ok := f.byID[id]; ok {
			all = append(all, d)
		}
	}
	start := (q.Page - 1) * q.PageSize
	if start > len(all) {
		start = len(all)
	}
	end := start + q.PageSize
	if end > len(all) {
		end = len(all)
	}
	return datastore.PageResult[*entities.Device]{Entities: all[start:end], Page: q.Page, PageSize: q.PageSize, Total: len(all)}, nil
}

type fakeProfiles struct {
	profile *entities.DeviceProfile
	err     error
}

func (f *fakeProfiles) FindProfileForDevice(context.Context, *entities.Device) (*entities.DeviceProfile, error) {
	return f.profile, f.err
}

func TestDeviceRecordsAdapter(t *testing.T) {
	devices := &fakeDevices{byID: map[uint64]*entities.Device{
		42: {ID: 42, Serial: "SN-42", Model: "X10", Hostname: "lab-node-5-compute-01", LastHeartbeatAddr: "198.18.1.143:5"},
	}}
	a := &deviceRecordsAdapter{devices: devices, profiles: &fakeProfiles{profile: &entities.DeviceProfile{TLSServerName: "compute.example.internal"}}}
	rec, err := a.AddressRecord(context.Background(), " 42 ")
	require.NoError(t, err)
	assert.Equal(t, "lab-node-5-compute-01", rec.Hostname)
	assert.Equal(t, "198.18.1.143:5", rec.HeartbeatAddr)
	assert.Equal(t, "compute.example.internal", rec.TLSServerName)

	_, err = a.AddressRecord(context.Background(), "not-a-number")
	var badID ErrCollectorDeviceID
	require.ErrorAs(t, err, &badID)
	assert.Contains(t, badID.Error(), "not-a-number")

	_, err = a.AddressRecord(context.Background(), "7")
	require.Error(t, err)

	// A profile lookup failure leaves the name empty rather than failing
	// the record: the FQDN is still a valid expectation.
	a = &deviceRecordsAdapter{devices: devices, profiles: &fakeProfiles{err: errors.New("no profile")}}
	rec, err = a.AddressRecord(context.Background(), "42")
	require.NoError(t, err)
	assert.Empty(t, rec.TLSServerName)
	a = &deviceRecordsAdapter{devices: devices}
	rec, err = a.AddressRecord(context.Background(), "42")
	require.NoError(t, err)
	assert.Empty(t, rec.TLSServerName)
}

func TestAttestableDevices_FiltersAndPages(t *testing.T) {
	byID := map[uint64]*entities.Device{}
	for i := uint64(1); i <= attestablePageSize+3; i++ {
		byID[i] = &entities.Device{ID: i, AttestPub: "pub", State: entities.DeviceStateActivated}
	}
	byID[2].AttestPub = ""                             // no anchor: skipped
	byID[7].AttestPub, byID[7].AttestCert = "", "cert" // certificate-only enrollment: kept
	byID[3].State = entities.DeviceStateRevoked        // revoked: skipped
	byID[4].State = entities.DeviceStateSuspended      // suspended: skipped
	byID[5].State = entities.DeviceStateQuarantined    // quarantined: kept
	byID[6].State = entities.DeviceStateRegistered     // registered: kept
	lister := &attestableDevices{devices: &fakeDevices{byID: byID}}
	ids, err := lister.AttestableDevices(context.Background())
	require.NoError(t, err)
	assert.Len(t, ids, attestablePageSize+3-3)
	assert.NotContains(t, ids, "2")
	assert.NotContains(t, ids, "3")
	assert.NotContains(t, ids, "4")
	assert.Contains(t, ids, "5")
	assert.Contains(t, ids, "6")
	assert.Contains(t, ids, "7", "a device enrolled with an attestation certificate but no bare key is attestable")
	assert.Contains(t, ids, "203")

	_, err = (&attestableDevices{devices: &fakeDevices{pageErr: errors.New("store down")}}).AttestableDevices(context.Background())
	require.Error(t, err)
	assert.False(t, attestable(nil))
}

func TestAttestedPeersAdapter(t *testing.T) {
	devices := &fakeDevices{byID: map[uint64]*entities.Device{
		1: {ID: 1, Hostname: "node-01", Serial: "SN-1"},
		2: {ID: 2, Hostname: "node-02.example.internal", Serial: "SN-2"},
		3: {ID: 3, Hostname: "node-03", Serial: "SN-3"},
	}}
	cache := reporting.NewCache(time.Hour)
	cache.Store(&reporting.Report{DeviceID: "1", Verified: true, CollectedAt: time.Now()})
	cache.Store(&reporting.Report{DeviceID: "2", Verified: false, CollectedAt: time.Now()})
	cache.Store(&reporting.Report{DeviceID: "3", Verified: true, CollectedAt: time.Now().Add(-2 * time.Hour)})
	a := &attestedPeersAdapter{devices: devices, reports: cache}

	att, ok := a.PeerAttestation([]string{"node-01.example.internal"})
	require.True(t, ok, "the bare IDevID label is matched from the FQDN")
	assert.True(t, att.Verified)
	assert.True(t, att.Fresh)

	att, ok = a.PeerAttestation([]string{"node-02.example.internal"})
	require.True(t, ok)
	assert.False(t, att.Verified)

	att, ok = a.PeerAttestation([]string{"sn-3"})
	assert.False(t, ok, "serial lookup is exact")
	att, ok = a.PeerAttestation([]string{"SN-3"})
	require.True(t, ok)
	assert.True(t, att.Verified)
	assert.False(t, att.Fresh)

	_, ok = a.PeerAttestation([]string{"unknown.example.internal"})
	assert.False(t, ok)
	_, ok = a.PeerAttestation(nil)
	assert.False(t, ok)

	// A known device with no report is "unknown", not "failed".
	devices.byID[9] = &entities.Device{ID: 9, Hostname: "node-09"}
	_, ok = a.PeerAttestation([]string{"node-09"})
	assert.False(t, ok)
}

func TestCollectorIdentityName(t *testing.T) {
	a := &app.App{}
	assert.Equal(t, "default", collectorIdentityName(a, nil))
	assert.Equal(t, "internal", collectorIdentityName(a, &config.CollectorConfig{Identity: " internal "}))
	a.WebServices = []*v1.Config{{Name: "public"}}
	assert.Equal(t, "public", collectorIdentityName(a, &config.CollectorConfig{}))
	assert.Nil(t, collectorPCRs(nil))
	assert.Equal(t, []int{0, 7}, collectorPCRs(&config.CollectorConfig{PCRs: []int{0, 7}}))
}

func TestCollectorTLSDialer_FailsClosedWithoutIdentity(t *testing.T) {
	_, err := collectorTLSDialer(&app.App{}, nil, quietLogger())
	var ident ErrCollectorIdentity
	require.ErrorAs(t, err, &ident)
	assert.Contains(t, ident.Error(), "certificate authority")
}

func TestCollectorAnchors_OperatorBundleThenResolver(t *testing.T) {
	root := selfSignedCA(t, "root-ca.compute.example.io", true)
	bundle := writeCallerBundle(t, root)
	src, err := collectorAnchors(&app.App{}, &config.CollectorConfig{CAFile: bundle}, quietLogger())
	require.NoError(t, err)
	pool, err := src(context.Background(), reporting.Endpoint{Address: "192.0.2.1:9443"})
	require.NoError(t, err)
	require.NotNil(t, pool)
	assert.Len(t, pool.Subjects(), 1) //nolint:staticcheck // enumeration is the assertion

	_, err = collectorAnchors(&app.App{}, &config.CollectorConfig{CAFile: filepath.Join(t.TempDir(), "missing.pem")}, quietLogger())
	var ident ErrCollectorIdentity
	require.ErrorAs(t, err, &ident, "an unusable configured bundle is an error, never a fall-through")
	assert.Contains(t, ident.Error(), "missing.pem")

	_, err = collectorAnchors(&app.App{}, nil, quietLogger())
	require.ErrorAs(t, err, &ident, "no bundle and no trust resolver: fail closed")
	assert.Contains(t, ident.Error(), "trust.internal")
}

func TestInitReportingCollector_OffOrUnbuildable(t *testing.T) {
	assert.Nil(t, initReportingCollector(context.Background(), quietLogger(), nil, nil, nil, nil))
	a := &app.App{}
	cfg := &daemon.Config{}
	assert.Nil(t, initReportingCollector(context.Background(), quietLogger(), a, cfg, nil, nil), "disabled by default")
	a.AttestationConfig.Reporting = &config.ReportingConfig{Enabled: true}
	assert.Nil(t, initReportingCollector(context.Background(), quietLogger(), a, cfg, nil, nil), "no device service")
	cfg.DeviceService = &fakeDevices{}
	assert.Nil(t, initReportingCollector(context.Background(), quietLogger(), a, cfg, nil, nil), "no CA: no identity, no collector")
}

// TestDeviceRecordsAdapter_ResolvesTheBoundProfile is the collector half of
// the #463 round trip over the real ProfileService: a device whose profile
// has no match rules — the installer-created shape — gets the profile's
// tls_server_name only once the profile is bound to the device's EK
// identity, and a rule-based profile still resolves for an unbound device.
// Dropping the bound branch from FindProfileForDevice must fail this test.
func TestDeviceRecordsAdapter_ResolvesTheBoundProfile(t *testing.T) {
	ctx := context.Background()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(ctx))
	profiles, err := device.NewProfileService(device.NewDatastore(storage, logging.DefaultLogger()))
	require.NoError(t, err)
	certPEM := reportingTestEKCertPEM(t)
	dev := &entities.Device{ID: 970392025956353, Serial: "lab-node-5-compute-01", Model: "SuperMicro X10", EKCert: certPEM}
	devices := &fakeDevices{byID: map[uint64]*entities.Device{dev.ID: dev, 2: {ID: 2, Serial: "lab-node-1-gw-01", Model: "SuperMicro X10"}}}
	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{ID: 4631, Name: "lab-node-5", Role: entities.DeviceRoleWorker, TLSServerName: "compute.trusted-platform.internal"}))
	a := &deviceRecordsAdapter{devices: devices, profiles: profiles}

	rec, err := a.AddressRecord(ctx, "970392025956353")
	require.NoError(t, err)
	assert.Empty(t, rec.TLSServerName, "before the assign no profile is bound to or matches the device")

	ekSerial, err := entities.EKSerialFromCertPEM(certPEM)
	require.NoError(t, err)
	require.NoError(t, profiles.AssignToDeviceWithEK(ctx, 4631, ekSerial, "", certPEM))

	rec, err = a.AddressRecord(ctx, "970392025956353")
	require.NoError(t, err)
	assert.Equal(t, "compute.trusted-platform.internal", rec.TLSServerName, "the bound profile's name reaches the collector")

	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{ID: 4632, Name: "gateways", Role: entities.DeviceRoleGateway, TLSServerName: "gw.trusted-platform.internal",
		MatchRules: &entities.ProfileMatchRules{SerialPrefix: "MINI-01"}}))
	rec, err = a.AddressRecord(ctx, "2")
	require.NoError(t, err)
	assert.Equal(t, "gw.trusted-platform.internal", rec.TLSServerName, "an unbound device still resolves through the match rules")
}

// reportingTestEKCertPEM returns a self-signed certificate standing in for a
// device's EK certificate.
func reportingTestEKCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4630001), Subject: pkix.Name{CommonName: "ek"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
