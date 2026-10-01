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

package configdelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// An EAB credential authorises exactly the device it was issued for: config
// delivery and remote signing refuse it for any other profile or tenant.

func resolverFor(profile *entities.DeviceProfile) *mockProfileResolver {
	return &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			if profile == nil {
				return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
			}
			return profile, nil
		},
	}
}

func configRequest(t *testing.T, svc *Service) *ConfigRequest {
	t.Helper()
	return &ConfigRequest{EKSerial: "ek-1", EABKeyID: "key-1", EABHMAC: validEABHMAC(), Nonce: issueValidNonce(t, svc)}
}

func TestResolveConfig_EABBinding(t *testing.T) {
	profile := &entities.DeviceProfile{ID: 1, TenantID: "acme", Config: "cfg"}
	for name, tc := range map[string]struct {
		profile *entities.DeviceProfile
		eab     *mockEABService
		wantErr bool
	}{
		"bound to the resolved profile and tenant":    {profile, &mockEABService{profileID: 1, tenantID: "acme"}, false},
		"bound to another profile":                    {profile, &mockEABService{profileID: 2, tenantID: "acme"}, true},
		"bound to the profile in another tenant":      {profile, &mockEABService{profileID: 1, tenantID: "other"}, true},
		"profile without a tenant accepts its EAB":    {&entities.DeviceProfile{ID: 1, Config: "cfg"}, &mockEABService{profileID: 1, tenantID: "acme"}, false},
		"a device resolving to no profile is refused": {nil, &mockEABService{profileID: 1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			svc := testService(t, resolverFor(tc.profile), tc.eab)
			cfg, pending, err := svc.ResolveConfig(context.Background(), configRequest(t, svc))
			if !tc.wantErr {
				if err != nil || cfg == nil {
					t.Fatalf("ResolveConfig = %v, %v", cfg, err)
				}
				return
			}
			var mismatch ErrEABProfileMismatch
			if !errors.As(err, &mismatch) {
				t.Fatalf("err = %v, want ErrEABProfileMismatch", err)
			}
			if cfg != nil || pending != nil {
				t.Fatalf("a refused request produced config %v or a pending session %v", cfg, pending)
			}
		})
	}
}

func TestSignDigest_EABBoundToAnotherProfileIsNeverSigned(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	signer := &fakeDBKeySigner{signature: []byte("sig")}
	svc := newSignService(t, profile, signer, &mockEABService{profileID: profile.ID + 1}, true)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, certB64, sha256Digest()))
	var mismatch ErrEABProfileMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want ErrEABProfileMismatch", err)
	}
	if signer.signCalls != 0 {
		t.Fatalf("the digest was signed %d times for a foreign credential", signer.signCalls)
	}
}

func TestHandler_EABProfileMismatchIsForbidden(t *testing.T) {
	profile := &entities.DeviceProfile{ID: 1, Config: "cfg"}
	h, svc := testHandlerWithDeps(t, resolverFor(profile), &mockEABService{profileID: 2})
	body, err := json.Marshal(configRequest(t, svc))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.FetchConfig(w, httptest.NewRequest(http.MethodPost, "/api/v1/provision/config", bytes.NewReader(body)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}
