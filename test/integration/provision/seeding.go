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

//go:build integration

package provision

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	devicesdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	eabsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/eab"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// lifecycleFixture is the daemon-side state seeded for the full
// delivered-config lifecycle: a device profile bound to a synthetic
// EK serial / MAC carrying a real platform config, and an active EAB
// credential bound to that profile. Both are created through the
// platform's own gRPC surfaces (platform.v1 DeviceService and
// platform.v1 EABService via the SDK service clients) — never by
// hand-writing store state — and both are deleted on cleanup so reruns
// against the shared daemon stay idempotent.
type lifecycleFixture struct {
	profileID  uint64
	ekSerial   string
	macAddress string

	// ekCertPEM is the synthetic hardware EK certificate prestaged on the
	// seeded profile (PEM), and ekCertB64DER is the standard-base64 DER
	// encoding of the SAME certificate as a booting device presents it.
	// Together they arm the EK-binding gate so the delivered and signed
	// paths are reachable with RequireEKMatch enforced.
	ekCertPEM    string
	ekCertB64DER string

	// config is the seeded device config in its JSON round-trip shape;
	// delivered configs on every transport must decode back to exactly
	// this value.
	config map[string]any

	// eabKeyID / eabHMAC are the EAB credential identifiers a booting
	// device presents. eabHMAC is the base64url (unpadded) encoding of
	// the raw HMAC key exactly as returned by EABService.CreateCredential
	// — the same value the install-time client receives on the kernel
	// cmdline (eab_hmac) and passes verbatim in eab_hmac; the server
	// base64url-decodes it and constant-time-compares the raw key bytes
	// (pkg/provisioning/configdelivery verifyNonceAndEAB ->
	// pkg/eab Service.Validate).
	eabKeyID string
	eabHMAC  string
}

// dialSeedConn opens the mTLS gRPC connection used by the seeding clients
// and registers its closure with the test cleanup.
func dialSeedConn(t *testing.T) *grpc.ClientConn {
	t.Helper()

	tlsConfig := helpers.LoadMTLSConfig()
	if tlsConfig == nil {
		t.Fatal(ErrMTLSNotConfigured{Protocol: "gRPC (seeding)"}.Error())
	}
	tlsConfig.MinVersion = tls.VersionTLS13

	conn, err := grpc.NewClient(grpcEndpoint(),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		t.Fatalf("seeding: failed to create gRPC connection to %s: %v", grpcEndpoint(), err)
	}
	t.Cleanup(func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("Warning: seeding connection close error: %v", closeErr)
		}
	})
	return conn
}

// seedLifecycleFixture creates the device profile and EAB credential the
// delivered-config lifecycle tests run against, using unique per-run
// identifiers. Cleanup deletes the credential first, then the profile
// (t.Cleanup runs LIFO), each with its own background-context timeout so
// cleanup still runs when the test context is already canceled.
func seedLifecycleFixture(t *testing.T, ctx context.Context) *lifecycleFixture {
	t.Helper()

	conn := dialSeedConn(t)
	deviceClient := devicesdk.NewClientFromGRPC(platformv1.NewDeviceServiceClient(conn))
	eabClient := eabsdk.NewClientFromGRPC(platformv1.NewEABServiceClient(conn))

	ekCertPEM, ekCertB64DER := newSelfSignedEKCert(t)
	fixture := &lifecycleFixture{
		ekSerial:     uniqueID("provision-mp-fixture-ek"),
		macAddress:   uniqueMAC(),
		ekCertPEM:    ekCertPEM,
		ekCertB64DER: ekCertB64DER,
		// The seeded config carries a recognizable platform section plus a
		// secure-boot section provisioned for resign-mode "remote", so the
		// SignDigest scenario is blocked only by the two authentication /
		// availability gates asserted there (never by a missing secure-boot
		// section). Values are strings/bools only so the JSON round-trip
		// shape is stable for deep-equality assertions.
		config: map[string]any{
			"platform": map[string]any{
				"hostname": uniqueID("provision-mp-node"),
			},
			"secure-boot": map[string]any{
				"enabled":     true,
				"resign-mode": "remote",
				"db": map[string]any{
					"key-uri": "kms://secure-boot/" + uniqueID("provision-mp-db"),
					"cn":      uniqueID("provision-mp-db-cn"),
				},
			},
		},
	}

	configJSON, err := json.Marshal(fixture.config)
	if err != nil {
		t.Fatalf("seeding: config serialization failed: %v", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	created, err := deviceClient.CreateProfile(callCtx, &platformv1.DeviceProfile{
		Name:       uniqueID("provision-mp-profile"),
		EkSerial:   fixture.ekSerial,
		MacAddress: fixture.macAddress,
		EkCert:     fixture.ekCertPEM,
		Config:     configJSON,
	})
	if err != nil {
		t.Fatalf("seeding: CreateProfile failed: %v", err)
	}
	if created.GetId() == 0 {
		t.Fatal("seeding: CreateProfile returned a zero profile ID")
	}
	fixture.profileID = created.GetId()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), callTimeout)
		defer cleanupCancel()
		if delErr := deviceClient.DeleteProfile(cleanupCtx, fixture.profileID); delErr != nil {
			t.Logf("Warning: seeding cleanup DeleteProfile(%d) error: %v", fixture.profileID, delErr)
		}
	})

	// Guard against silent identity/config loss on the create path: the
	// delivered-config lifecycle is meaningless when the daemon dropped the
	// EK serial, MAC, or config during profile creation.
	if created.GetEkSerial() != fixture.ekSerial {
		t.Fatalf("seeding: profile ek_serial not persisted: got %q, want %q",
			created.GetEkSerial(), fixture.ekSerial)
	}
	if created.GetMacAddress() != fixture.macAddress {
		t.Fatalf("seeding: profile mac_address not persisted: got %q, want %q",
			created.GetMacAddress(), fixture.macAddress)
	}
	if err := assertConfigJSONEqual(created.GetConfig(), fixture.config); err != nil {
		t.Fatalf("seeding: profile config not persisted: %v", err)
	}
	// The prestaged EK certificate is the whole point of the EK-bound
	// delivery contract: a silent drop here would quietly re-open the
	// "delivered path unreachable" gap.
	if created.GetEkCert() != fixture.ekCertPEM {
		t.Fatalf("seeding: profile ek_cert not persisted: got %d bytes, want %d bytes",
			len(created.GetEkCert()), len(fixture.ekCertPEM))
	}

	cred, err := eabClient.CreateCredential(callCtx, &platformv1.CreateEABCredentialRequest{
		ProfileId:        fixture.profileID,
		TenantId:         uniqueID("provision-mp-tenant"),
		ExpiresInSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("seeding: CreateCredential failed: %v", err)
	}
	if cred.GetKeyId() == "" || cred.GetHmacKey() == "" {
		t.Fatalf("seeding: CreateCredential returned incomplete credential: key_id=%q hmac_key_len=%d",
			cred.GetKeyId(), len(cred.GetHmacKey()))
	}
	fixture.eabKeyID = cred.GetKeyId()
	fixture.eabHMAC = cred.GetHmacKey()
	credentialID := cred.GetId()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), callTimeout)
		defer cleanupCancel()
		if _, delErr := eabClient.DeleteCredential(cleanupCtx, credentialID); delErr != nil {
			t.Logf("Warning: seeding cleanup DeleteCredential(%d) error: %v", credentialID, delErr)
		}
	})

	return fixture
}

// newSelfSignedEKCert generates an ECDSA self-signed certificate and
// returns it in both forms the EK-binding gate consumes: PEM (prestaged
// on the profile) and standard-base64-encoded DER (presented by the
// booting device).
func newSelfSignedEKCert(t *testing.T) (pemStr, b64DER string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("seeding: EK key generation failed: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "provision-mp-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("seeding: EK certificate generation failed: %v", err)
	}

	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b64DER = base64.StdEncoding.EncodeToString(der)
	return pemStr, b64DER
}

// fetchRequest builds a FetchConfigRequest carrying the fixture's EAB
// credentials AND its presented EK certificate for the given device
// identity and nonce. Presenting the matching EK certificate keeps the
// delivered path reachable with RequireEKMatch enforced. A request whose
// identity matches no profile never reaches the EK gate: the credential's
// profile binding refuses it first.
func (f *lifecycleFixture) fetchRequest(ekSerial, mac, nonce string) *platformv1.FetchConfigRequest {
	return &platformv1.FetchConfigRequest{
		EkSerial:   ekSerial,
		MacAddress: mac,
		EkCert:     f.ekCertB64DER,
		EabKeyId:   f.eabKeyID,
		EabHmac:    f.eabHMAC,
		Nonce:      nonce,
	}
}

// assertConfigJSONEqual verifies that configJSON decodes to exactly the
// expected seeded config value (JSON round-trip shapes on both sides).
func assertConfigJSONEqual(configJSON []byte, want map[string]any) error {
	if len(configJSON) == 0 {
		return ErrConfigMismatch{Reason: "config JSON is empty"}
	}
	var got any
	if err := json.Unmarshal(configJSON, &got); err != nil {
		return ErrConfigMismatch{Reason: "config JSON did not decode: " + err.Error()}
	}
	// Normalize the expectation through a JSON round-trip so both sides use
	// identical dynamic types (map[string]any / float64 / bool / string).
	wantJSON, err := json.Marshal(want)
	if err != nil {
		return ErrConfigMismatch{Reason: "expected config did not serialize: " + err.Error()}
	}
	var wantNormalized any
	if err := json.Unmarshal(wantJSON, &wantNormalized); err != nil {
		return ErrConfigMismatch{Reason: "expected config did not round-trip: " + err.Error()}
	}
	if !reflect.DeepEqual(got, wantNormalized) {
		return ErrConfigMismatch{
			Reason: "delivered config does not match seeded profile config: got " +
				string(configJSON) + ", want " + string(wantJSON),
		}
	}
	return nil
}
