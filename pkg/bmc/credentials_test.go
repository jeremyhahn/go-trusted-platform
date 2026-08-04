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
	"errors"
	"sort"
	"strings"
	"testing"
)

func TestNewCredentials(t *testing.T) {
	src := []byte("hunter2")
	c := NewCredentials("ADMIN", src)
	defer c.Destroy()

	if c.Username != "ADMIN" {
		t.Errorf("Username = %q, want ADMIN", c.Username)
	}
	if !c.IsAlive() {
		t.Error("credentials not alive")
	}
	if string(c.Password.Bytes()) != "hunter2" {
		t.Errorf("password = %q, want hunter2", c.Password.Bytes())
	}
	// Source should be wiped.
	for i, b := range src {
		if b != 0 {
			t.Errorf("src byte %d = %x, want 0", i, b)
		}
	}
}

func TestNewCredentialsFromStrings(t *testing.T) {
	c := NewCredentialsFromStrings("u", "p")
	defer c.Destroy()
	if string(c.Password.Bytes()) != "p" {
		t.Errorf("password mismatch")
	}
}

func TestNewCredentials_NilPassword(t *testing.T) {
	c := NewCredentials("u", nil)
	defer c.Destroy()
	if !c.IsAlive() {
		t.Error("nil password should still yield alive credentials")
	}
	if c.Password.Size() != 0 {
		t.Errorf("size = %d, want 0", c.Password.Size())
	}
}

func TestCredentials_DestroyIdempotent(t *testing.T) {
	c := NewCredentials("u", []byte("p"))
	c.Destroy()
	c.Destroy()
	if c.IsAlive() {
		t.Error("still alive after destroy")
	}
}

func TestCredentials_NilReceiver(t *testing.T) {
	var c *Credentials
	c.Destroy()
	if c.IsAlive() {
		t.Error("nil credentials reported alive")
	}
}

func TestCredentialPath(t *testing.T) {
	cases := []struct {
		name, want string
	}{
		{"bmc01", "bmc/bmc01"},
		{"", "bmc/"},
		{"192.168.1.10", "bmc/192.168.1.10"},
	}
	for _, tc := range cases {
		if got := CredentialPath(tc.name); got != tc.want {
			t.Errorf("CredentialPath(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNameFromCredentialPath(t *testing.T) {
	cases := []struct {
		path, want string
	}{
		{"bmc/bmc01", "bmc01"},
		{"bmc/192.168.1.10", "192.168.1.10"},
		{"other/path", ""},
		{"bmc", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := NameFromCredentialPath(tc.path); got != tc.want {
			t.Errorf("NameFromCredentialPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestMarshalUnmarshalCredentials_RoundTrip(t *testing.T) {
	orig := NewCredentials("alice", []byte("s3cret"))
	defer orig.Destroy()

	blob, err := MarshalCredentials(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Make a copy because Unmarshal zeros its input.
	blobCopy := append([]byte(nil), blob...)
	// Scrub orig blob now (caller contract).
	zero(blob)

	got, err := UnmarshalCredentials(blobCopy)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	defer got.Destroy()
	if got.Username != "alice" {
		t.Errorf("username = %q", got.Username)
	}
	if string(got.Password.Bytes()) != "s3cret" {
		t.Errorf("password = %q", got.Password.Bytes())
	}
	// Unmarshal must have zeroed its input.
	for i, b := range blobCopy {
		if b != 0 {
			t.Errorf("blobCopy[%d] = %x after Unmarshal, want 0", i, b)
			break
		}
	}
}

func TestMarshalCredentials_NilCreds(t *testing.T) {
	_, err := MarshalCredentials(nil)
	var want ErrInvalidCredentials
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestUnmarshalCredentials_BadJSON(t *testing.T) {
	_, err := UnmarshalCredentials([]byte("not json"))
	var want ErrInvalidCredentials
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

// --- MemoryStore ---

func TestMemoryStore_PutGet(t *testing.T) {
	s := NewMemoryStore()
	defer s.DestroyAll()

	c := NewCredentials("admin", []byte("pw"))
	if err := s.Put(context.Background(), "bmc01", c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(context.Background(), "bmc01")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Username != "admin" || string(got.Password.Bytes()) != "pw" {
		t.Errorf("roundtrip failed: %+v", got)
	}
}

func TestMemoryStore_GetMissing(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Get(context.Background(), "nope")
	var want ErrCredentialsNotFound
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrCredentialsNotFound", err)
	}
}

func TestMemoryStore_Replace_DestroysPrior(t *testing.T) {
	s := NewMemoryStore()
	defer s.DestroyAll()

	first := NewCredentials("a", []byte("1"))
	if err := s.Put(context.Background(), "bmc", first); err != nil {
		t.Fatal(err)
	}
	second := NewCredentials("b", []byte("2"))
	if err := s.Put(context.Background(), "bmc", second); err != nil {
		t.Fatal(err)
	}
	if first.IsAlive() {
		t.Error("replaced credentials not destroyed")
	}
	got, _ := s.Get(context.Background(), "bmc")
	if got.Username != "b" {
		t.Errorf("Username = %q, want b", got.Username)
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	s := NewMemoryStore()
	c := NewCredentials("u", []byte("p"))
	_ = s.Put(context.Background(), "bmc", c)
	if err := s.Delete(context.Background(), "bmc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if c.IsAlive() {
		t.Error("deleted credentials not destroyed")
	}
	if _, err := s.Get(context.Background(), "bmc"); err == nil {
		t.Error("expected not-found after delete")
	}
	// Delete of missing is no-op.
	if err := s.Delete(context.Background(), "bmc"); err != nil {
		t.Errorf("delete missing returned %v, want nil", err)
	}
}

func TestMemoryStore_List(t *testing.T) {
	s := NewMemoryStore()
	defer s.DestroyAll()
	_ = s.Put(context.Background(), "a", NewCredentials("x", []byte("y")))
	_ = s.Put(context.Background(), "b", NewCredentials("x", []byte("y")))
	_ = s.Put(context.Background(), "c", NewCredentials("x", []byte("y")))
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

func TestMemoryStore_EmptyName(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if _, err := s.Get(ctx, ""); err == nil {
		t.Error("Get empty name should error")
	}
	if err := s.Put(ctx, "", NewCredentials("u", []byte("p"))); err == nil {
		t.Error("Put empty name should error")
	}
	if err := s.Delete(ctx, ""); err == nil {
		t.Error("Delete empty name should error")
	}
}

func TestMemoryStore_PutDestroyedCredsRejected(t *testing.T) {
	s := NewMemoryStore()
	c := NewCredentials("u", []byte("p"))
	c.Destroy()
	if err := s.Put(context.Background(), "bmc", c); err == nil {
		t.Error("expected error for destroyed creds")
	}
	if err := s.Put(context.Background(), "bmc", nil); err == nil {
		t.Error("expected error for nil creds")
	}
}

func TestMemoryStore_GetReturnsClone(t *testing.T) {
	s := NewMemoryStore()
	defer s.DestroyAll()
	orig := NewCredentials("u", []byte("p"))
	_ = s.Put(context.Background(), "bmc", orig)

	got, err := s.Get(context.Background(), "bmc")
	if err != nil {
		t.Fatal(err)
	}
	// Destroying the clone must not affect the store.
	got.Destroy()
	got2, err := s.Get(context.Background(), "bmc")
	if err != nil {
		t.Fatalf("second Get after clone destroy: %v", err)
	}
	defer got2.Destroy()
	if string(got2.Password.Bytes()) != "p" {
		t.Errorf("password after clone destroy = %q, want p", got2.Password.Bytes())
	}
}

func TestMemoryStore_History_ReturnsEmpty(t *testing.T) {
	s := NewMemoryStore()
	defer s.DestroyAll()

	_ = s.Put(context.Background(), "bmc01", NewCredentials("u", []byte("p")))

	versions, err := s.History(context.Background(), "bmc01")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("expected empty slice, got %d versions", len(versions))
	}
}

func TestMemoryStore_History_EmptyName(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.History(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty name")
	}
	var want ErrInvalidCredentials
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestCredentials_Clone(t *testing.T) {
	c := NewCredentials("alice", []byte("secret"))
	defer c.Destroy()
	cl := c.Clone()
	defer cl.Destroy()
	if cl.Username != "alice" {
		t.Errorf("clone Username = %q", cl.Username)
	}
	if string(cl.Password.Bytes()) != "secret" {
		t.Errorf("clone password = %q", cl.Password.Bytes())
	}
	// Independence: destroying the clone doesn't affect original.
	cl.Destroy()
	if !c.IsAlive() {
		t.Error("original destroyed by clone.Destroy()")
	}
}

func TestCredentials_Clone_NilOrDestroyed(t *testing.T) {
	var nilc *Credentials
	if nilc.Clone() != nil {
		t.Error("nil.Clone() should be nil")
	}
	c := NewCredentials("u", []byte("p"))
	c.Destroy()
	if c.Clone() != nil {
		t.Error("destroyed.Clone() should be nil")
	}
}

func TestValidateName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"bmc01", true},
		{"192.168.1.10", true},
		{"", false},
		{"has space", false},
		{"has\ttab", false},
		{"has/slash", false},
	}
	for _, tc := range cases {
		err := validateName(tc.name)
		if tc.ok && err != nil {
			t.Errorf("validateName(%q) = %v, want nil", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("validateName(%q) = nil, want error", tc.name)
		}
	}
}

func TestErrMessages(t *testing.T) {
	cases := []error{
		ErrCredentialsNotFound{Name: "x"},
		ErrInvalidCredentials{Reason: "r"},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error from %T", e)
		}
	}
}
