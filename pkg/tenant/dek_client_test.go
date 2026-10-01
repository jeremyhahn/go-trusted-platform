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

package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
)

// fakeDEK implements the quicbaas DEK client verbs the tenant adapter uses.
// The embedded interface is nil: any other verb panics, which would flag a
// change in what the adapter calls.
type fakeDEK struct {
	quicbaas.DEKClient

	existing  *dek.DEKInfo
	getErr    error
	created   *dek.CreateDEKResponse
	createErr error
	deleted   *dek.DeleteDEKResponse
	deleteErr error
	rotated   *dek.RotateDEKResponse
	rotateErr error
	status    *dek.DEKStatusResponse
	statusErr error

	lastPath string
}

func (f *fakeDEK) GetDEK(_ context.Context, path string) (*dek.DEKInfo, error) {
	f.lastPath = path
	return f.existing, f.getErr
}

func (f *fakeDEK) CreateDEK(_ context.Context, req *dek.CreateDEKRequest) (*dek.CreateDEKResponse, error) {
	f.lastPath = req.Path
	return f.created, f.createErr
}

func (f *fakeDEK) DeleteDEK(_ context.Context, req *dek.DeleteDEKRequest) (*dek.DeleteDEKResponse, error) {
	f.lastPath = req.Path
	return f.deleted, f.deleteErr
}

func (f *fakeDEK) RotateDEK(_ context.Context, req *dek.RotateDEKRequest) (*dek.RotateDEKResponse, error) {
	f.lastPath = req.Path
	return f.rotated, f.rotateErr
}

func (f *fakeDEK) GetDEKStatus(_ context.Context, path string) (*dek.DEKStatusResponse, error) {
	f.lastPath = path
	return f.status, f.statusErr
}

var errFakeDEK = errors.New("dek backend down")

func TestNewTenantDEKClient_Nil(t *testing.T) {
	if NewTenantDEKClient(nil) != nil {
		t.Error("NewTenantDEKClient(nil) must return nil so callers fail closed")
	}
}

func TestSDKTenantDEKClient_Ensure(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	existing := &fakeDEK{existing: &dek.DEKInfo{Path: "tenant/t1", Algorithm: "aes-256-gcm", CreatedAt: created}}
	resp, err := NewTenantDEKClient(existing).EnsureTenantDEK(ctx, &EnsureTenantDEKRequest{TenantID: "t1"})
	if err != nil || resp.Created || resp.DEKID != "tenant/t1" || !resp.CreatedAt.Equal(created) {
		t.Fatalf("existing DEK: resp=%+v err=%v", resp, err)
	}

	fresh := &fakeDEK{getErr: errFakeDEK, created: &dek.CreateDEKResponse{DEK: &dek.DEKInfo{Path: "tenant/t2", Algorithm: "aes-256-gcm"}}}
	resp, err = NewTenantDEKClient(fresh).EnsureTenantDEK(ctx, &EnsureTenantDEKRequest{TenantID: "t2", Algorithm: "aes-256-gcm"})
	if err != nil || !resp.Created || resp.DEKID != "tenant/t2" || fresh.lastPath != "tenant/t2" {
		t.Fatalf("new DEK: resp=%+v err=%v path=%s", resp, err, fresh.lastPath)
	}
}

func TestSDKTenantDEKClient_Ensure_Errors(t *testing.T) {
	ctx := context.Background()
	var invalid ErrInvalidRequest
	if _, err := NewTenantDEKClient(&fakeDEK{}).EnsureTenantDEK(ctx, &EnsureTenantDEKRequest{}); !errors.As(err, &invalid) {
		t.Errorf("empty tenant: error = %v, want ErrInvalidRequest", err)
	}
	if _, err := NewTenantDEKClient(&fakeDEK{createErr: errFakeDEK}).EnsureTenantDEK(ctx, &EnsureTenantDEKRequest{TenantID: "t"}); !errors.Is(err, errFakeDEK) {
		t.Errorf("create failure: error = %v, want backend error", err)
	}
	var dekErr ErrDEKOperationFailed
	if _, err := NewTenantDEKClient(&fakeDEK{created: &dek.CreateDEKResponse{}}).EnsureTenantDEK(ctx, &EnsureTenantDEKRequest{TenantID: "t"}); !errors.As(err, &dekErr) || dekErr.Operation != "ensure" {
		t.Errorf("empty create response: error = %v, want ErrDEKOperationFailed ensure", err)
	}
}

func TestSDKTenantDEKClient_Delete(t *testing.T) {
	f := &fakeDEK{deleted: &dek.DeleteDEKResponse{Path: "tenant/t1", Deleted: true}}
	resp, err := NewTenantDEKClient(f).DeleteTenantDEK(context.Background(), &DeleteTenantDEKRequest{TenantID: "t1"})
	if err != nil || resp.DEKID != "tenant/t1" || resp.DeletedAt.IsZero() {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
}

func TestSDKTenantDEKClient_Delete_Errors(t *testing.T) {
	ctx := context.Background()
	var invalid ErrInvalidRequest
	if _, err := NewTenantDEKClient(&fakeDEK{}).DeleteTenantDEK(ctx, nil); !errors.As(err, &invalid) {
		t.Errorf("nil request: error = %v, want ErrInvalidRequest", err)
	}
	if _, err := NewTenantDEKClient(&fakeDEK{deleteErr: errFakeDEK}).DeleteTenantDEK(ctx, &DeleteTenantDEKRequest{TenantID: "t"}); !errors.Is(err, errFakeDEK) {
		t.Errorf("backend failure: error = %v", err)
	}
	var dekErr ErrDEKOperationFailed
	if _, err := NewTenantDEKClient(&fakeDEK{deleted: &dek.DeleteDEKResponse{}}).DeleteTenantDEK(ctx, &DeleteTenantDEKRequest{TenantID: "t"}); !errors.As(err, &dekErr) || dekErr.Operation != "delete" {
		t.Errorf("not deleted: error = %v, want ErrDEKOperationFailed delete", err)
	}
}

func TestSDKTenantDEKClient_Rotate(t *testing.T) {
	f := &fakeDEK{rotated: &dek.RotateDEKResponse{OldVersion: 1, NewVersion: 2}}
	resp, err := NewTenantDEKClient(f).RotateTenantDEK(context.Background(), &RotateTenantDEKRequest{TenantID: "t1"})
	if err != nil || resp.OldVersion != 1 || resp.NewVersion != 2 || f.lastPath != "tenant/t1" {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
}

func TestSDKTenantDEKClient_Rotate_Errors(t *testing.T) {
	ctx := context.Background()
	var invalid ErrInvalidRequest
	if _, err := NewTenantDEKClient(&fakeDEK{}).RotateTenantDEK(ctx, &RotateTenantDEKRequest{}); !errors.As(err, &invalid) {
		t.Errorf("empty tenant: error = %v", err)
	}
	if _, err := NewTenantDEKClient(&fakeDEK{rotateErr: errFakeDEK}).RotateTenantDEK(ctx, &RotateTenantDEKRequest{TenantID: "t"}); !errors.Is(err, errFakeDEK) {
		t.Errorf("backend failure: error = %v", err)
	}
	var dekErr ErrDEKOperationFailed
	if _, err := NewTenantDEKClient(&fakeDEK{}).RotateTenantDEK(ctx, &RotateTenantDEKRequest{TenantID: "t"}); !errors.As(err, &dekErr) || dekErr.Operation != "rotate" {
		t.Errorf("nil response: error = %v", err)
	}
}

func TestSDKTenantDEKClient_Status(t *testing.T) {
	rotated := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeDEK{status: &dek.DEKStatusResponse{
		DEK:                  &dek.DEKInfo{Algorithm: "aes-256-gcm", Version: 3, RotatedAt: rotated},
		ReencryptionProgress: &dek.ReencryptionProgress{InProgress: true},
	}}
	resp, err := NewTenantDEKClient(f).TenantDEKStatus(context.Background(), &TenantDEKStatusRequest{TenantID: "t1"})
	if err != nil || resp.CurrentVersion != 3 || resp.RotatedAt == nil || !resp.RotatedAt.Equal(rotated) || !resp.ReencryptionInProgress {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}

	never := &fakeDEK{status: &dek.DEKStatusResponse{DEK: &dek.DEKInfo{Version: 1}}}
	resp, err = NewTenantDEKClient(never).TenantDEKStatus(context.Background(), &TenantDEKStatusRequest{TenantID: "t1"})
	if err != nil || resp.RotatedAt != nil || resp.ReencryptionInProgress {
		t.Fatalf("never rotated: resp=%+v err=%v", resp, err)
	}
}

func TestSDKTenantDEKClient_Status_Errors(t *testing.T) {
	ctx := context.Background()
	var invalid ErrInvalidRequest
	if _, err := NewTenantDEKClient(&fakeDEK{}).TenantDEKStatus(ctx, nil); !errors.As(err, &invalid) {
		t.Errorf("nil request: error = %v", err)
	}
	if _, err := NewTenantDEKClient(&fakeDEK{statusErr: errFakeDEK}).TenantDEKStatus(ctx, &TenantDEKStatusRequest{TenantID: "t"}); !errors.Is(err, errFakeDEK) {
		t.Errorf("backend failure: error = %v", err)
	}
	var dekErr ErrDEKOperationFailed
	if _, err := NewTenantDEKClient(&fakeDEK{status: &dek.DEKStatusResponse{}}).TenantDEKStatus(ctx, &TenantDEKStatusRequest{TenantID: "t"}); !errors.As(err, &dekErr) || dekErr.Operation != "status" {
		t.Errorf("empty status: error = %v", err)
	}
}
