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
	"testing"
)

// fakeBackend is a programmable virtualMediaBackend used by dispatcher tests.
type fakeBackend struct {
	name      string
	supports  bool
	mountErr  error
	called    bool
	statusOut *VirtualMediaInfo
	statusErr error
}

func (f *fakeBackend) Name() string               { return f.name }
func (f *fakeBackend) Supports(_ *MediaSpec) bool { return f.supports }
func (f *fakeBackend) Mount(_ context.Context, _ *MediaSpec) error {
	f.called = true
	return f.mountErr
}
func (f *fakeBackend) Unmount(_ context.Context) error {
	f.called = true
	return f.mountErr
}
func (f *fakeBackend) Status(_ context.Context) (*VirtualMediaInfo, error) {
	f.called = true
	return f.statusOut, f.statusErr
}

// runDispatch is the same logic as redfishClient.MountVirtualMedia but
// against an injected backend list, so we can exercise it without spinning
// up an HTTP server.
func runDispatch(ctx context.Context, spec *MediaSpec, backends []virtualMediaBackend) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	attempts := make([]VirtualMediaAttempt, 0, len(backends))
	for _, b := range backends {
		if !b.Supports(spec) {
			continue
		}
		err := b.Mount(ctx, spec)
		if err == nil {
			return nil
		}
		if isVirtualMediaFallthrough(err) {
			attempts = append(attempts, VirtualMediaAttempt{Backend: b.Name(), Err: err})
			continue
		}
		return ErrVirtualMediaBackendFailed{Backend: b.Name(), Cause: err}
	}
	return ErrVirtualMediaAllBackendsFailed{Attempts: attempts}
}

func TestDispatcher_FirstSupportedSucceeds(t *testing.T) {
	a := &fakeBackend{name: "a", supports: true}
	b := &fakeBackend{name: "b", supports: true}
	spec := &MediaSpec{URL: "https://example.com/boot.iso"}
	if err := runDispatch(context.Background(), spec, []virtualMediaBackend{a, b}); err != nil {
		t.Fatalf("runDispatch error: %v", err)
	}
	if !a.called {
		t.Errorf("first backend not called")
	}
	if b.called {
		t.Errorf("second backend should not have been called")
	}
}

func TestDispatcher_SkipsUnsupported(t *testing.T) {
	a := &fakeBackend{name: "a", supports: false}
	b := &fakeBackend{name: "b", supports: true}
	spec := &MediaSpec{URL: "https://example.com/boot.iso"}
	if err := runDispatch(context.Background(), spec, []virtualMediaBackend{a, b}); err != nil {
		t.Fatalf("runDispatch error: %v", err)
	}
	if a.called {
		t.Errorf("unsupported backend should not have been called")
	}
	if !b.called {
		t.Errorf("second backend not called")
	}
}

func TestDispatcher_FallthroughOnLicense(t *testing.T) {
	a := &fakeBackend{
		name:     "a",
		supports: true,
		mountErr: ErrVirtualMediaLicenseRequired{Vendor: "Supermicro", License: "DCMS"},
	}
	b := &fakeBackend{name: "b", supports: true}
	spec := &MediaSpec{URL: "https://example.com/boot.iso"}
	if err := runDispatch(context.Background(), spec, []virtualMediaBackend{a, b}); err != nil {
		t.Fatalf("runDispatch error: %v", err)
	}
	if !a.called || !b.called {
		t.Errorf("expected both backends called, got a=%v b=%v", a.called, b.called)
	}
}

func TestDispatcher_FallthroughOnUnsupported(t *testing.T) {
	a := &fakeBackend{
		name:     "a",
		supports: true,
		mountErr: ErrVirtualMediaUnsupported{Backend: "a", Vendor: "X", Reason: "no"},
	}
	b := &fakeBackend{name: "b", supports: true}
	spec := &MediaSpec{URL: "https://example.com/boot.iso"}
	if err := runDispatch(context.Background(), spec, []virtualMediaBackend{a, b}); err != nil {
		t.Fatalf("runDispatch error: %v", err)
	}
	if !a.called || !b.called {
		t.Errorf("expected both backends called, got a=%v b=%v", a.called, b.called)
	}
}

func TestDispatcher_FatalShortCircuits(t *testing.T) {
	fatal := errors.New("network exploded")
	a := &fakeBackend{name: "a", supports: true, mountErr: fatal}
	b := &fakeBackend{name: "b", supports: true}
	spec := &MediaSpec{URL: "https://example.com/boot.iso"}
	err := runDispatch(context.Background(), spec, []virtualMediaBackend{a, b})
	if err == nil {
		t.Fatalf("runDispatch returned nil, want fatal error")
	}
	var bf ErrVirtualMediaBackendFailed
	if !errors.As(err, &bf) {
		t.Fatalf("err = %T, want ErrVirtualMediaBackendFailed", err)
	}
	if bf.Backend != "a" {
		t.Errorf("backend = %q, want %q", bf.Backend, "a")
	}
	if !errors.Is(bf, fatal) {
		t.Errorf("expected wrapped fatal error in chain")
	}
	if b.called {
		t.Errorf("second backend should not have been called after fatal")
	}
}

func TestDispatcher_AllFallthroughReturnsAggregate(t *testing.T) {
	a := &fakeBackend{
		name:     "a",
		supports: true,
		mountErr: ErrVirtualMediaUnsupported{Backend: "a", Vendor: "X", Reason: "no"},
	}
	b := &fakeBackend{
		name:     "b",
		supports: true,
		mountErr: ErrVirtualMediaLicenseRequired{Vendor: "Y", License: "Z"},
	}
	spec := &MediaSpec{URL: "https://example.com/boot.iso"}
	err := runDispatch(context.Background(), spec, []virtualMediaBackend{a, b})
	var agg ErrVirtualMediaAllBackendsFailed
	if !errors.As(err, &agg) {
		t.Fatalf("err = %T, want ErrVirtualMediaAllBackendsFailed", err)
	}
	if len(agg.Attempts) != 2 {
		t.Errorf("attempts = %d, want 2", len(agg.Attempts))
	}
}

func TestDispatcher_NoSupportingBackends(t *testing.T) {
	a := &fakeBackend{name: "a", supports: false}
	spec := &MediaSpec{URL: "https://example.com/boot.iso"}
	err := runDispatch(context.Background(), spec, []virtualMediaBackend{a})
	var agg ErrVirtualMediaAllBackendsFailed
	if !errors.As(err, &agg) {
		t.Fatalf("err = %T, want ErrVirtualMediaAllBackendsFailed", err)
	}
	if len(agg.Attempts) != 0 {
		t.Errorf("attempts = %d, want 0", len(agg.Attempts))
	}
}

func TestDispatcher_ValidationShortCircuits(t *testing.T) {
	a := &fakeBackend{name: "a", supports: true}
	spec := &MediaSpec{URL: ""}
	err := runDispatch(context.Background(), spec, []virtualMediaBackend{a})
	var inv ErrVirtualMediaInvalidSpec
	if !errors.As(err, &inv) {
		t.Fatalf("err = %T, want ErrVirtualMediaInvalidSpec", err)
	}
	if a.called {
		t.Errorf("backend should not have been called for invalid spec")
	}
}

func TestRedfishClient_DefaultBackendChainOrder(t *testing.T) {
	c := &redfishClient{}
	chain := c.virtualMediaBackends()
	want := []string{"redfish-std", "redfish-smc", "smc-cgi"}
	if len(chain) != len(want) {
		t.Fatalf("chain length = %d, want %d", len(chain), len(want))
	}
	for i, b := range chain {
		if b.Name() != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, b.Name(), want[i])
		}
	}
}
