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

package credentials

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// secretEntry tracks a versioned secret in the fake store.
type secretEntry struct {
	versions []versionedData
}

// versionedData is a single version of a secret.
type versionedData struct {
	version   uint64
	data      []byte
	metadata  map[string]string
	createdAt time.Time
}

// fakeSecrets is a minimal in-memory SecretsService used for unit
// tests. Implements versioning semantics matching the QuicBaaS API.
type fakeSecrets struct {
	mu          sync.Mutex
	entries     map[string]*secretEntry
	storeErr    error
	getErr      error
	listErr     error
	delErr      error
	rotateErr   error
	versionsErr error
}

func newFakeSecrets() *fakeSecrets {
	return &fakeSecrets{entries: map[string]*secretEntry{}}
}

// data returns a flat map of secret ID to latest data for backward
// compatibility with existing tests that inspect f.data.
func (f *fakeSecrets) data() map[string][]byte {
	out := map[string][]byte{}
	for id, e := range f.entries {
		if len(e.versions) > 0 {
			latest := e.versions[len(e.versions)-1]
			out[id] = append([]byte(nil), latest.data...)
		}
	}
	return out
}

func (f *fakeSecrets) StoreSecret(_ context.Context, req *baasservice.StoreSecretRequest) (*baasservice.StoreSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.storeErr != nil {
		return nil, f.storeErr
	}
	e := &secretEntry{
		versions: []versionedData{{
			version:   1,
			data:      append([]byte(nil), req.Data...),
			createdAt: time.Now(),
		}},
	}
	f.entries[req.SecretID] = e
	return &baasservice.StoreSecretResponse{
		SecretID:  req.SecretID,
		Version:   1,
		Timestamp: time.Now(),
	}, nil
}

func (f *fakeSecrets) GetSecret(_ context.Context, req *baasservice.GetSecretRequest) (*baasservice.GetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	e, ok := f.entries[req.SecretID]
	if !ok || len(e.versions) == 0 {
		return nil, fmt.Errorf("secret not found: %s", req.SecretID)
	}
	latest := e.versions[len(e.versions)-1]
	return &baasservice.GetSecretResponse{
		SecretID:  req.SecretID,
		Data:      append([]byte(nil), latest.data...),
		Version:   latest.version,
		Timestamp: time.Now(),
	}, nil
}

func (f *fakeSecrets) DeleteSecret(_ context.Context, req *baasservice.DeleteSecretRequest) (*baasservice.DeleteSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return nil, f.delErr
	}
	if req.PermanentlyDelete && req.AllVersions {
		delete(f.entries, req.SecretID)
	} else {
		// Soft delete: remove only the latest version.
		e, ok := f.entries[req.SecretID]
		if ok && len(e.versions) > 0 {
			e.versions = e.versions[:len(e.versions)-1]
			if len(e.versions) == 0 {
				delete(f.entries, req.SecretID)
			}
		}
	}
	return &baasservice.DeleteSecretResponse{SecretID: req.SecretID}, nil
}

func (f *fakeSecrets) ListSecrets(_ context.Context, req *baasservice.ListSecretsRequest) (*baasservice.ListSecretsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []*baasservice.Secret{}
	for id := range f.entries {
		if req.Prefix != "" && !strings.HasPrefix(id, req.Prefix) {
			continue
		}
		out = append(out, &baasservice.Secret{SecretID: id, Name: id})
	}
	return &baasservice.ListSecretsResponse{Secrets: out}, nil
}

func (f *fakeSecrets) RotateSecret(_ context.Context, req *baasservice.RotateSecretRequest) (*baasservice.RotateSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rotateErr != nil {
		return nil, f.rotateErr
	}
	e, ok := f.entries[req.SecretID]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", req.SecretID)
	}
	oldVersion := e.versions[len(e.versions)-1].version
	newVersion := oldVersion + 1
	e.versions = append(e.versions, versionedData{
		version:   newVersion,
		data:      append([]byte(nil), req.NewData...),
		metadata:  req.Metadata,
		createdAt: time.Now(),
	})
	return &baasservice.RotateSecretResponse{
		SecretID:   req.SecretID,
		OldVersion: oldVersion,
		NewVersion: newVersion,
		Timestamp:  time.Now(),
	}, nil
}

func (f *fakeSecrets) ListSecretVersions(_ context.Context, req *baasservice.ListSecretVersionsRequest) (*baasservice.ListSecretVersionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.versionsErr != nil {
		return nil, f.versionsErr
	}
	e, ok := f.entries[req.SecretID]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", req.SecretID)
	}
	out := make([]*baasservice.SecretVersion, 0, len(e.versions))
	for _, v := range e.versions {
		out = append(out, &baasservice.SecretVersion{
			SecretID:  req.SecretID,
			Version:   v.version,
			Metadata:  v.metadata,
			CreatedAt: v.createdAt,
		})
	}
	return &baasservice.ListSecretVersionsResponse{
		Versions:  out,
		Timestamp: time.Now(),
	}, nil
}

// --- tests ---

func TestNewQuicBaaSStore_NilService(t *testing.T) {
	if _, err := NewQuicBaaSStore(nil); err == nil {
		t.Error("expected error for nil service")
	}
}

func TestQuicBaaSStore_PutGetRoundTrip(t *testing.T) {
	f := newFakeSecrets()
	s, err := NewQuicBaaSStore(f)
	if err != nil {
		t.Fatalf("NewQuicBaaSStore: %v", err)
	}
	c := bmc.NewCredentials("admin", []byte("hunter2"))
	defer c.Destroy()

	if err := s.Put(context.Background(), "bmc01", c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Verify stored under canonical path.
	d := f.data()
	if _, ok := d["bmc/bmc01"]; !ok {
		t.Errorf("secret not stored at bmc/bmc01; have keys %v", mapKeys(d))
	}

	got, err := s.Get(context.Background(), "bmc01")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer got.Destroy()
	if got.Username != "admin" || string(got.Password.Bytes()) != "hunter2" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestQuicBaaSStore_PutRotatesExistingSecret(t *testing.T) {
	f := newFakeSecrets()
	s, err := NewQuicBaaSStore(f)
	if err != nil {
		t.Fatalf("NewQuicBaaSStore: %v", err)
	}

	c1 := bmc.NewCredentials("admin", []byte("password1"))
	defer c1.Destroy()
	if err := s.Put(context.Background(), "bmc01", c1); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	c2 := bmc.NewCredentials("admin", []byte("password2"))
	defer c2.Destroy()
	if err := s.Put(context.Background(), "bmc01", c2); err != nil {
		t.Fatalf("second Put (rotate): %v", err)
	}

	// Verify two versions exist.
	f.mu.Lock()
	e, ok := f.entries["bmc/bmc01"]
	f.mu.Unlock()
	if !ok {
		t.Fatal("entry missing after rotate")
	}
	if len(e.versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(e.versions))
	}

	// Latest should be password2.
	got, err := s.Get(context.Background(), "bmc01")
	if err != nil {
		t.Fatalf("Get after rotate: %v", err)
	}
	defer got.Destroy()
	if string(got.Password.Bytes()) != "password2" {
		t.Errorf("expected password2, got %q", string(got.Password.Bytes()))
	}
}

func TestQuicBaaSStore_PutRotateMetadata(t *testing.T) {
	f := newFakeSecrets()
	s, err := NewQuicBaaSStore(f)
	if err != nil {
		t.Fatalf("NewQuicBaaSStore: %v", err)
	}

	c1 := bmc.NewCredentials("admin", []byte("pw1"))
	defer c1.Destroy()
	if err := s.Put(context.Background(), "bmc01", c1); err != nil {
		t.Fatalf("Put: %v", err)
	}

	c2 := bmc.NewCredentials("newadmin", []byte("pw2"))
	defer c2.Destroy()
	if err := s.Put(context.Background(), "bmc01", c2); err != nil {
		t.Fatalf("Put rotate: %v", err)
	}

	// Verify the rotation metadata was set on the second version.
	f.mu.Lock()
	e := f.entries["bmc/bmc01"]
	latestMeta := e.versions[len(e.versions)-1].metadata
	f.mu.Unlock()

	if latestMeta["username"] != "newadmin" {
		t.Errorf("expected username metadata 'newadmin', got %q", latestMeta["username"])
	}
	if _, ok := latestMeta["rotated"]; !ok {
		t.Error("expected 'rotated' timestamp in metadata")
	}
}

func TestQuicBaaSStore_Get_NotFound(t *testing.T) {
	f := newFakeSecrets()
	s, _ := NewQuicBaaSStore(f)
	_, err := s.Get(context.Background(), "missing")
	var want bmc.ErrCredentialsNotFound
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrCredentialsNotFound", err)
	}
}

func TestQuicBaaSStore_Get_EmptyName(t *testing.T) {
	s, _ := NewQuicBaaSStore(newFakeSecrets())
	if _, err := s.Get(context.Background(), ""); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestQuicBaaSStore_Get_EmptyData(t *testing.T) {
	f := newFakeSecrets()
	f.mu.Lock()
	f.entries["bmc/b1"] = &secretEntry{
		versions: []versionedData{{version: 1, data: []byte{}, createdAt: time.Now()}},
	}
	f.mu.Unlock()
	s, _ := NewQuicBaaSStore(f)
	_, err := s.Get(context.Background(), "b1")
	var want bmc.ErrCredentialsNotFound
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrCredentialsNotFound", err)
	}
}

func TestQuicBaaSStore_Get_UnmarshalErrorPropagates(t *testing.T) {
	f := newFakeSecrets()
	f.mu.Lock()
	f.entries["bmc/b1"] = &secretEntry{
		versions: []versionedData{{version: 1, data: []byte("corrupt-not-json"), createdAt: time.Now()}},
	}
	f.mu.Unlock()
	s, _ := NewQuicBaaSStore(f)
	_, err := s.Get(context.Background(), "b1")
	var want bmc.ErrInvalidCredentials
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestQuicBaaSStore_Get_ServiceError(t *testing.T) {
	f := newFakeSecrets()
	f.getErr = errors.New("transport broken")
	s, _ := NewQuicBaaSStore(f)
	_, err := s.Get(context.Background(), "x")
	if err == nil {
		t.Fatal("expected error")
	}
	var want bmc.ErrCredentialsNotFound
	if errors.As(err, &want) {
		t.Errorf("non-notfound error wrongly mapped to NotFound")
	}
}

func TestQuicBaaSStore_Put_EmptyName(t *testing.T) {
	s, _ := NewQuicBaaSStore(newFakeSecrets())
	c := bmc.NewCredentials("u", []byte("p"))
	defer c.Destroy()
	if err := s.Put(context.Background(), "", c); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestQuicBaaSStore_Put_NilCreds(t *testing.T) {
	s, _ := NewQuicBaaSStore(newFakeSecrets())
	if err := s.Put(context.Background(), "x", nil); err == nil {
		t.Error("expected error for nil creds")
	}
}

func TestQuicBaaSStore_Put_DestroyedCreds(t *testing.T) {
	s, _ := NewQuicBaaSStore(newFakeSecrets())
	c := bmc.NewCredentials("u", []byte("p"))
	c.Destroy()
	if err := s.Put(context.Background(), "x", c); err == nil {
		t.Error("expected error for destroyed creds")
	}
}

func TestQuicBaaSStore_Put_StoreError(t *testing.T) {
	f := newFakeSecrets()
	// RotateSecret will fail with not-found, then StoreSecret will fail.
	f.storeErr = errors.New("disk full")
	s, _ := NewQuicBaaSStore(f)
	c := bmc.NewCredentials("u", []byte("p"))
	defer c.Destroy()
	if err := s.Put(context.Background(), "x", c); err == nil {
		t.Error("expected error")
	}
}

func TestQuicBaaSStore_Put_RotateError(t *testing.T) {
	f := newFakeSecrets()
	s, _ := NewQuicBaaSStore(f)

	// Create initial entry.
	c1 := bmc.NewCredentials("u", []byte("p1"))
	defer c1.Destroy()
	if err := s.Put(context.Background(), "x", c1); err != nil {
		t.Fatalf("initial Put: %v", err)
	}

	// Now make RotateSecret fail with a non-not-found error.
	f.rotateErr = errors.New("quota exceeded")
	c2 := bmc.NewCredentials("u", []byte("p2"))
	defer c2.Destroy()
	if err := s.Put(context.Background(), "x", c2); err == nil {
		t.Error("expected error from rotate failure")
	}
}

func TestQuicBaaSStore_Delete(t *testing.T) {
	f := newFakeSecrets()
	s, _ := NewQuicBaaSStore(f)
	c := bmc.NewCredentials("u", []byte("p"))
	defer c.Destroy()
	_ = s.Put(context.Background(), "x", c)
	if err := s.Delete(context.Background(), "x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestQuicBaaSStore_Delete_SoftDeletePreservesHistory(t *testing.T) {
	f := newFakeSecrets()
	s, _ := NewQuicBaaSStore(f)

	// Create two versions.
	c1 := bmc.NewCredentials("u", []byte("p1"))
	defer c1.Destroy()
	if err := s.Put(context.Background(), "x", c1); err != nil {
		t.Fatalf("Put: %v", err)
	}
	c2 := bmc.NewCredentials("u", []byte("p2"))
	defer c2.Destroy()
	if err := s.Put(context.Background(), "x", c2); err != nil {
		t.Fatalf("Put rotate: %v", err)
	}

	// Delete (soft) removes only latest version.
	if err := s.Delete(context.Background(), "x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Entry should still exist with the first version.
	f.mu.Lock()
	e, ok := f.entries["bmc/x"]
	versionCount := 0
	if ok {
		versionCount = len(e.versions)
	}
	f.mu.Unlock()

	if !ok {
		t.Fatal("expected entry to still exist after soft delete")
	}
	if versionCount != 1 {
		t.Errorf("expected 1 version remaining, got %d", versionCount)
	}
}

func TestQuicBaaSStore_Delete_NotFound_NoOp(t *testing.T) {
	f := newFakeSecrets()
	// Arrange: DeleteSecret returns a not-found-like error; adapter
	// should swallow it.
	f.delErr = errors.New("not found")
	s, _ := NewQuicBaaSStore(f)
	if err := s.Delete(context.Background(), "x"); err != nil {
		t.Errorf("expected nil for not-found delete, got %v", err)
	}
}

func TestQuicBaaSStore_Delete_OtherError(t *testing.T) {
	f := newFakeSecrets()
	f.delErr = errors.New("permission denied")
	s, _ := NewQuicBaaSStore(f)
	if err := s.Delete(context.Background(), "x"); err == nil {
		t.Error("expected error")
	}
}

func TestQuicBaaSStore_Delete_EmptyName(t *testing.T) {
	s, _ := NewQuicBaaSStore(newFakeSecrets())
	if err := s.Delete(context.Background(), ""); err == nil {
		t.Error("expected error")
	}
}

func TestQuicBaaSStore_List(t *testing.T) {
	f := newFakeSecrets()
	s, _ := NewQuicBaaSStore(f)
	// Populate 3 bmc creds + 1 unrelated secret in the same service.
	for _, n := range []string{"a", "b", "c"} {
		c := bmc.NewCredentials("u", []byte("p"))
		_ = s.Put(context.Background(), n, c)
	}
	f.mu.Lock()
	f.entries["other/not-a-bmc"] = &secretEntry{
		versions: []versionedData{{version: 1, data: []byte("irrelevant"), createdAt: time.Now()}},
	}
	f.mu.Unlock()

	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(got)
	want := []string{"a", "b", "c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("List = %v, want %v", got, want)
	}
}

func TestQuicBaaSStore_List_Error(t *testing.T) {
	f := newFakeSecrets()
	f.listErr = errors.New("listing denied")
	s, _ := NewQuicBaaSStore(f)
	if _, err := s.List(context.Background()); err == nil {
		t.Error("expected error")
	}
}

func TestQuicBaaSStore_History(t *testing.T) {
	f := newFakeSecrets()
	s, err := NewQuicBaaSStore(f)
	if err != nil {
		t.Fatalf("NewQuicBaaSStore: %v", err)
	}

	// Create initial credential.
	c1 := bmc.NewCredentials("admin", []byte("pw1"))
	defer c1.Destroy()
	if err := s.Put(context.Background(), "bmc01", c1); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Rotate twice.
	c2 := bmc.NewCredentials("admin", []byte("pw2"))
	defer c2.Destroy()
	if err := s.Put(context.Background(), "bmc01", c2); err != nil {
		t.Fatalf("Put rotate 1: %v", err)
	}
	c3 := bmc.NewCredentials("admin", []byte("pw3"))
	defer c3.Destroy()
	if err := s.Put(context.Background(), "bmc01", c3); err != nil {
		t.Fatalf("Put rotate 2: %v", err)
	}

	versions, err := s.History(context.Background(), "bmc01")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(versions))
	}

	// Newest first.
	if versions[0].Version != 3 {
		t.Errorf("expected newest version 3, got %d", versions[0].Version)
	}
	if versions[1].Version != 2 {
		t.Errorf("expected version 2, got %d", versions[1].Version)
	}
	if versions[2].Version != 1 {
		t.Errorf("expected oldest version 1, got %d", versions[2].Version)
	}

	// CreatedAt should be populated.
	for i, v := range versions {
		if v.CreatedAt.IsZero() {
			t.Errorf("version[%d]: CreatedAt is zero", i)
		}
	}
}

func TestQuicBaaSStore_History_EmptyName(t *testing.T) {
	s, _ := NewQuicBaaSStore(newFakeSecrets())
	_, err := s.History(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty name")
	}
	var want bmc.ErrInvalidCredentials
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestQuicBaaSStore_History_NotFound(t *testing.T) {
	f := newFakeSecrets()
	s, _ := NewQuicBaaSStore(f)
	versions, err := s.History(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("expected nil error for missing credential, got %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("expected empty slice, got %d versions", len(versions))
	}
}

func TestQuicBaaSStore_History_ServiceError(t *testing.T) {
	f := newFakeSecrets()
	f.versionsErr = errors.New("internal error")
	s, _ := NewQuicBaaSStore(f)
	_, err := s.History(context.Background(), "x")
	if err == nil {
		t.Error("expected error")
	}
}

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("not found"), true},
		{errors.New("NOT FOUND"), true},
		{errors.New("No such secret here"), true},
		{errors.New("does not exist"), true},
		{errors.New("status: 404"), true},
		{errors.New("permission denied"), false},
		{errNotFoundSentinel, true},
		{fmt.Errorf("wrap: %w", errNotFoundSentinel), true},
	}
	for _, tc := range cases {
		if got := isNotFound(tc.err); got != tc.want {
			t.Errorf("isNotFound(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestSecretID(t *testing.T) {
	if got := secretID(nil); got != "" {
		t.Errorf("secretID(nil) = %q", got)
	}
	if got := secretID(&baasservice.Secret{SecretID: "a", Name: "b"}); got != "a" {
		t.Errorf("SecretID preferred; got %q", got)
	}
	if got := secretID(&baasservice.Secret{Name: "b"}); got != "b" {
		t.Errorf("Name fallback; got %q", got)
	}
	if got := secretID(&baasservice.Secret{}); got != "" {
		t.Errorf("empty secret; got %q", got)
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte("secret")
	zeroBytes(b)
	for _, v := range b {
		if v != 0 {
			t.Errorf("not zeroed: %v", b)
			break
		}
	}
}

func mapKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
