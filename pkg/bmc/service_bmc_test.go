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

package bmc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
)

// profileCall invokes one profile-based Service method and returns only
// its error, so every method can share one table.
type profileCall struct {
	name string
	call func(ctx context.Context, svc *Service, id uint64) error
}

func clientProfileCalls() []profileCall {
	return []profileCall{
		{"PowerOn", func(ctx context.Context, s *Service, id uint64) error { return s.PowerOn(ctx, id) }},
		{"PowerOff", func(ctx context.Context, s *Service, id uint64) error { return s.PowerOff(ctx, id) }},
		{"PowerReset", func(ctx context.Context, s *Service, id uint64) error { return s.PowerReset(ctx, id) }},
		{"PowerCycle", func(ctx context.Context, s *Service, id uint64) error { return s.PowerCycle(ctx, id) }},
		{"PowerStatus", func(ctx context.Context, s *Service, id uint64) error {
			_, err := s.PowerStatus(ctx, id)
			return err
		}},
		{"SetBootDevice", func(ctx context.Context, s *Service, id uint64) error {
			return s.SetBootDevice(ctx, id, BootDevicePXE, false)
		}},
		{"GetBootDevice", func(ctx context.Context, s *Service, id uint64) error {
			_, err := s.GetBootDevice(ctx, id)
			return err
		}},
		{"MountISO", func(ctx context.Context, s *Service, id uint64) error {
			return s.MountISO(ctx, id, "https://images.example.test/a.iso")
		}},
		{"UnmountISO", func(ctx context.Context, s *Service, id uint64) error { return s.UnmountISO(ctx, id) }},
		{"VirtualMediaStatus", func(ctx context.Context, s *Service, id uint64) error {
			_, err := s.VirtualMediaStatus(ctx, id)
			return err
		}},
		{"GetSensors", func(ctx context.Context, s *Service, id uint64) error {
			_, err := s.GetSensors(ctx, id)
			return err
		}},
		{"GetSystemInfo", func(ctx context.Context, s *Service, id uint64) error {
			_, err := s.GetSystemInfo(ctx, id)
			return err
		}},
	}
}

func userProfileCalls() []profileCall {
	return []profileCall{
		{"ListUsers", func(ctx context.Context, s *Service, id uint64) error {
			_, err := s.ListUsers(ctx, id)
			return err
		}},
		{"CreateUser", func(ctx context.Context, s *Service, id uint64) error {
			return s.CreateUser(ctx, id, User{Slot: 3, Username: "ops", Privilege: PrivilegeOperator}, "pw")
		}},
		{"DeleteUser", func(ctx context.Context, s *Service, id uint64) error { return s.DeleteUser(ctx, id, 3) }},
		{"SetUserPassword", func(ctx context.Context, s *Service, id uint64) error {
			return s.SetUserPassword(ctx, id, 3, "pw")
		}},
		{"SetUserPrivilege", func(ctx context.Context, s *Service, id uint64) error {
			return s.SetUserPrivilege(ctx, id, 3, 1, PrivilegeUser)
		}},
	}
}

func certProfileCalls() []profileCall {
	return []profileCall{
		{"GetWebCertificate", func(ctx context.Context, s *Service, id uint64) error {
			_, err := s.GetWebCertificate(ctx, id)
			return err
		}},
		{"ReplaceWebCertificate", func(ctx context.Context, s *Service, id uint64) error {
			return s.ReplaceWebCertificate(ctx, id, []byte("cert"), []byte("key"))
		}},
	}
}

func allProfileCalls() []profileCall {
	calls := clientProfileCalls()
	calls = append(calls, userProfileCalls()...)
	return append(calls, certProfileCalls()...)
}

// newServiceWith builds a Service over the given factory and profile store.
func newServiceWith(t *testing.T, factory ClientFactory, profiles ProfileStore) *Service {
	t.Helper()
	svc, err := NewService(ServiceParams{Factory: factory, Profiles: profiles, Logger: slog.Default()})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func assertProfileNotFound(t *testing.T, err error, id uint64) {
	t.Helper()
	var notFound ErrProfileNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v (%T), want ErrProfileNotFound", err, err)
	}
	if notFound.ProfileID != id {
		t.Errorf("ProfileID = %d, want %d", notFound.ProfileID, id)
	}
}

func TestService_ProfileMethods_UnknownProfile(t *testing.T) {
	ctx := context.Background()
	stores := map[string]ProfileStore{
		"empty store": &mockProfileStore{configs: map[uint64]*Config{}},
		"store error": &mockProfileStore{err: ErrInvalidConfig{Field: "store"}},
		"no store":    nil,
	}
	for storeName, store := range stores {
		svc := newServiceWith(t, &MockClientFactory{Client: NewMockClient()}, store)
		for _, tc := range allProfileCalls() {
			t.Run(storeName+"/"+tc.name, func(t *testing.T) {
				assertProfileNotFound(t, tc.call(ctx, svc, 42), 42)
			})
		}
	}
}

func TestService_ClientMethods_FactoryError(t *testing.T) {
	ctx := context.Background()
	factoryErr := ErrConnectionFailed{Address: "bmc-7.example.test"}
	profiles := &mockProfileStore{configs: map[uint64]*Config{7: {Address: "bmc-7.example.test"}}}
	svc := newServiceWith(t, &MockClientFactory{Err: factoryErr}, profiles)

	for _, tc := range clientProfileCalls() {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(ctx, svc, 7)
			var connErr ErrConnectionFailed
			if !errors.As(err, &connErr) || connErr.Address != factoryErr.Address {
				t.Fatalf("err = %v, want the factory error %v", err, factoryErr)
			}
		})
	}
}

// closedUDPPort returns a loopback UDP port with no listener, so an RMCP
// session dialled to it fails fast with ICMP port unreachable.
func closedUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return port
}

func TestService_UserMethods_ConfigErrors(t *testing.T) {
	ctx := context.Background()
	unreachable := &Config{
		Address:  "127.0.0.1",
		Port:     closedUDPPort(t),
		Username: "admin",
		Password: "pw",
		Protocol: ProtocolIPMI,
	}
	profiles := &mockProfileStore{configs: map[uint64]*Config{
		1: {Port: 623, Protocol: ProtocolIPMI},
		2: unreachable,
	}}
	svc := newServiceWith(t, &MockClientFactory{Client: NewMockClient()}, profiles)

	for _, tc := range userProfileCalls() {
		t.Run(tc.name+"/invalid config", func(t *testing.T) {
			var cfgErr ErrInvalidConfig
			err := tc.call(ctx, svc, 1)
			if !errors.As(err, &cfgErr) || cfgErr.Field != "address" {
				t.Fatalf("err = %v, want ErrInvalidConfig{Field: address}", err)
			}
		})
		t.Run(tc.name+"/unreachable BMC", func(t *testing.T) {
			var connErr ErrConnectionFailed
			err := tc.call(ctx, svc, 2)
			if !errors.As(err, &connErr) {
				t.Fatalf("err = %v (%T), want ErrConnectionFailed", err, err)
			}
			if connErr.Address != unreachable.Endpoint() || connErr.Cause == nil {
				t.Errorf("ErrConnectionFailed = %+v, want address %q with a cause", connErr, unreachable.Endpoint())
			}
		})
	}
}

func TestService_CertMethods_InvalidBackend(t *testing.T) {
	cfg := baseCfg("bmc.example.test", 443, nil)
	cfg.Certificate, cfg.Key = certBlockWithChallenge("dns-01")
	cfg.Backend = CertBackend("floppy")
	svc := newServiceWith(t, &MockClientFactory{}, &mockProfileStore{configs: map[uint64]*Config{5: cfg}})

	for _, tc := range certProfileCalls() {
		t.Run(tc.name, func(t *testing.T) {
			var cfgErr ErrInvalidConfig
			err := tc.call(context.Background(), svc, 5)
			if !errors.As(err, &cfgErr) || cfgErr.Field != "backend" {
				t.Fatalf("err = %v, want ErrInvalidConfig{Field: backend}", err)
			}
		})
	}
}

func TestService_GetWebCertificate_ReportsPeerCertificate(t *testing.T) {
	host, port, srv := startVendorServer(t, "")
	defer srv.Close()
	svc := newServiceWith(t, &MockClientFactory{},
		&mockProfileStore{configs: map[uint64]*Config{9: baseCfg(host, port, srv)}})

	info, err := svc.GetWebCertificate(context.Background(), 9)
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	want := NewCertificateInfo(srv.Certificate(), time.Now().UTC())
	if info.Fingerprint != want.Fingerprint || info.Subject != want.Subject || info.SerialNumber != want.SerialNumber {
		t.Errorf("info = %+v, want the test server certificate %+v", info, want)
	}
	if !info.NotAfter.Equal(srv.Certificate().NotAfter) {
		t.Errorf("NotAfter = %v, want %v", info.NotAfter, srv.Certificate().NotAfter)
	}
}

func TestService_GetWebCertificate_UnreachableBMC(t *testing.T) {
	host, port, srv := startVendorServer(t, "")
	cfg := baseCfg(host, port, srv)
	srv.Close()
	svc := newServiceWith(t, &MockClientFactory{}, &mockProfileStore{configs: map[uint64]*Config{9: cfg}})

	info, err := svc.GetWebCertificate(context.Background(), 9)
	var connErr ErrConnectionFailed
	if !errors.As(err, &connErr) || connErr.Address != host {
		t.Fatalf("err = %v, want ErrConnectionFailed for %s", err, host)
	}
	if info != nil {
		t.Errorf("info = %+v, want nil on failure", info)
	}
}

func TestService_ReplaceWebCertificate(t *testing.T) {
	tests := []struct {
		name       string
		replaceErr error
	}{
		{name: "success"},
		{name: "backend failure", replaceErr: ErrConnectionFailed{Address: "bmc.example.test"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeCertManager{backend: CertBackendRedfish, replaceErr: tc.replaceErr}
			withTempRegistry(t, map[CertBackend]CertManagerFactory{
				CertBackendRedfish: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return fake, nil },
			})
			cfg := baseCfg("bmc.example.test", 443, nil)
			cfg.Certificate, cfg.Key = certBlockWithChallenge("dns-01")
			cfg.Backend = CertBackendRedfish
			svc := newServiceWith(t, &MockClientFactory{}, &mockProfileStore{configs: map[uint64]*Config{4: cfg}})

			err := svc.ReplaceWebCertificate(context.Background(), 4, []byte("cert"), []byte("key"))
			if !errors.Is(err, tc.replaceErr) {
				t.Fatalf("err = %v, want %v", err, tc.replaceErr)
			}
			if fake.replaceCalls != 1 {
				t.Errorf("replaceCalls = %d, want 1", fake.replaceCalls)
			}
			if !fake.closed {
				t.Error("backend manager was not closed")
			}
		})
	}
}

// infoTestCert issues a throwaway certificate with the given template
// fields filled in on top of a fixed subject and serial.
func infoTestCert(t *testing.T, notAfter time.Time, dnsNames []string, ips []net.IP) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xABCDEF),
		Subject:      pkix.Name{CommonName: "bmc-01"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestNewCertificateInfo(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	t.Run("valid certificate with SANs", func(t *testing.T) {
		cert := infoTestCert(t, now.Add(10*24*time.Hour+time.Hour),
			[]string{"bmc-01.example.test"}, []net.IP{net.ParseIP("10.0.0.5")})
		info := NewCertificateInfo(cert, now)
		sum := sha256.Sum256(cert.Raw)
		want := &CertificateInfo{
			Subject:                 "CN=bmc-01",
			Issuer:                  "CN=bmc-01",
			SerialNumber:            "ABCDEF",
			NotBefore:               cert.NotBefore,
			NotAfter:                cert.NotAfter,
			DaysRemaining:           10,
			SubjectAlternativeNames: []string{"bmc-01.example.test", "10.0.0.5"},
			Fingerprint:             hex.EncodeToString(sum[:]),
		}
		if !reflect.DeepEqual(info, want) {
			t.Errorf("info = %+v\nwant %+v", info, want)
		}
	})

	t.Run("expired certificate without SANs", func(t *testing.T) {
		info := NewCertificateInfo(infoTestCert(t, now.Add(-36*time.Hour), nil, nil), now)
		if info.DaysRemaining != -1 {
			t.Errorf("DaysRemaining = %d, want -1", info.DaysRemaining)
		}
		if info.SubjectAlternativeNames != nil {
			t.Errorf("SubjectAlternativeNames = %v, want nil", info.SubjectAlternativeNames)
		}
	})

	t.Run("missing serial number", func(t *testing.T) {
		info := NewCertificateInfo(&x509.Certificate{Raw: []byte{0x30}}, now)
		if info.SerialNumber != "" {
			t.Errorf("SerialNumber = %q, want empty", info.SerialNumber)
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		if info := NewCertificateInfo(nil, now); info != nil {
			t.Errorf("info = %+v, want nil", info)
		}
	})
}
