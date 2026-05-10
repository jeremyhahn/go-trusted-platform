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

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

type fakeFIDO2Backend struct{}

func (f *fakeFIDO2Backend) ListDevices(_ context.Context) ([]FIDO2Device, error) {
	return []FIDO2Device{{ID: "key1", Product: "YubiKey"}}, nil
}

func (f *fakeFIDO2Backend) WaitDevice(_ context.Context, _ time.Duration) (*FIDO2Device, error) {
	return &FIDO2Device{ID: "key1"}, nil
}

func (f *fakeFIDO2Backend) Info(_ context.Context, device string) (*FIDO2Info, error) {
	return &FIDO2Info{
		Device: FIDO2Device{ID: device},
		AAGUID: "aa-guid",
	}, nil
}

func (f *fakeFIDO2Backend) Register(_ context.Context, _ *FIDO2RegisterRequest) (*FIDO2RegisterResult, error) {
	return &FIDO2RegisterResult{CredentialID: "cred-1", AAGUID: "aa"}, nil
}

func (f *fakeFIDO2Backend) Authenticate(_ context.Context, _ string) (*FIDO2AuthenticateResult, error) {
	return &FIDO2AuthenticateResult{Authenticated: true, Counter: 42}, nil
}

func TestFIDO2Service_NotConfigured(t *testing.T) {
	svc := NewFIDO2Service(logging.DefaultLogger(), nil)
	ctx := context.Background()
	if _, err := svc.ListDevices(ctx); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("ListDevices: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := svc.WaitDevice(ctx, 0); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("WaitDevice: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := svc.Info(ctx, "dev1"); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("Info: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := svc.Register(ctx, &FIDO2RegisterRequest{Username: "u"}); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("Register: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := svc.Authenticate(ctx, "cred"); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("Authenticate: want ErrFIDO2NotConfigured, got %v", err)
	}
}

func TestFIDO2Service_Validation(t *testing.T) {
	svc := NewFIDO2Service(logging.DefaultLogger(), &fakeFIDO2Backend{})
	ctx := context.Background()
	if _, err := svc.Info(ctx, ""); !errors.Is(err, ErrFIDO2DeviceRequired) {
		t.Errorf("Info: want ErrFIDO2DeviceRequired, got %v", err)
	}
	if _, err := svc.Register(ctx, &FIDO2RegisterRequest{}); !errors.Is(err, ErrFIDO2UsernameRequired) {
		t.Errorf("Register: want ErrFIDO2UsernameRequired, got %v", err)
	}
	if _, err := svc.Authenticate(ctx, ""); !errors.Is(err, ErrFIDO2CredentialRequired) {
		t.Errorf("Authenticate: want ErrFIDO2CredentialRequired, got %v", err)
	}
}

func TestFIDO2Service_BackendSuccess(t *testing.T) {
	svc := NewFIDO2Service(logging.DefaultLogger(), &fakeFIDO2Backend{})
	ctx := context.Background()
	if d, err := svc.ListDevices(ctx); err != nil || len(d) != 1 {
		t.Errorf("ListDevices: %v %+v", err, d)
	}
	if d, err := svc.WaitDevice(ctx, time.Second); err != nil || d == nil {
		t.Errorf("WaitDevice: %v %+v", err, d)
	}
	if i, err := svc.Info(ctx, "dev1"); err != nil || i.AAGUID != "aa-guid" {
		t.Errorf("Info: %v %+v", err, i)
	}
	if r, err := svc.Register(ctx, &FIDO2RegisterRequest{Username: "alice", Role: FIDO2RoleSO}); err != nil || r.CredentialID == "" {
		t.Errorf("Register: %v %+v", err, r)
	}
	if r, err := svc.Authenticate(ctx, "cred-1"); err != nil || !r.Authenticated {
		t.Errorf("Authenticate: %v %+v", err, r)
	}
}
