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

package volume

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
)

// The platform's existing local volume store already fits the seam.
var _ Provider = (*nbd.LocalVolumes)(nil)

type fakeProvider struct{ provider string }

func (p *fakeProvider) Create(string, int64) error { return nil }

func (p *fakeProvider) Attach(identity string) (string, error) {
	return "/dev/" + p.provider + "/" + identity, nil
}

type factoryCall struct {
	provider string
	settings map[string]string
}

type fakeFactory struct {
	calls []factoryCall
	err   error
}

func (f *fakeFactory) NewProvider(provider string, settings map[string]string) (Provider, error) {
	f.calls = append(f.calls, factoryCall{provider: provider, settings: settings})
	if f.err != nil {
		return nil, f.err
	}
	return &fakeProvider{provider: provider}, nil
}

func TestNew(t *testing.T) {
	if _, err := New(nil, &fakeFactory{}); !errors.Is(err, ErrNilConfig) {
		t.Fatalf("New(nil) error = %v, want ErrNilConfig", err)
	}

	bad := DefaultConfig()
	bad.Classes[0].Provider = "nfs"
	if _, err := New(bad, &fakeFactory{}); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("New(invalid) error = %v, want ErrUnknownProvider", err)
	}

	r, err := New(DefaultConfig(), nil)
	if err != nil || r == nil {
		t.Fatalf("New(cfg, nil) = %v, %v; want a resolver", r, err)
	}
}

func TestResolver_ProviderForClass(t *testing.T) {
	f := &fakeFactory{}
	r, err := New(DefaultConfig(), f)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	p, err := r.Provider(ClassGeneral)
	if err != nil || p == nil {
		t.Fatalf("Provider(general) = %v, %v", p, err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("factory calls = %d, want 1", len(f.calls))
	}
	want := factoryCall{provider: ProviderLocal, settings: map[string]string{"volume_group": "platform"}}
	if !reflect.DeepEqual(f.calls[0], want) {
		t.Fatalf("factory call = %+v, want %+v", f.calls[0], want)
	}

	if _, err := r.Provider(""); err != nil {
		t.Fatalf("Provider(\"\") error = %v", err)
	}
	if len(f.calls) != 2 || f.calls[1].provider != ProviderLocal {
		t.Fatalf("Provider(\"\") factory calls = %+v, want the default class's provider", f.calls)
	}

	if _, err := r.Provider(ClassReplicated); err != nil {
		t.Fatalf("Provider(replicated) error = %v", err)
	}
	if len(f.calls) != 3 || f.calls[2].provider != ProviderDRBD {
		t.Fatalf("Provider(replicated) factory calls = %+v, want drbd", f.calls)
	}

	if _, err := r.Provider("fast"); !errors.Is(err, ErrUnknownClass) {
		t.Fatalf("Provider(fast) error = %v, want ErrUnknownClass", err)
	}
}

func TestResolver_ObjectClassIsNotBlock(t *testing.T) {
	f := &fakeFactory{}
	r, err := New(DefaultConfig(), f)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := r.Provider(ClassObject); !errors.Is(err, ErrObjectClassNotBlock) {
		t.Fatalf("Provider(object) error = %v, want ErrObjectClassNotBlock", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("factory calls = %d, want 0", len(f.calls))
	}
}

func TestResolver_NoFactory(t *testing.T) {
	r, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := r.Provider(ClassGeneral); !errors.Is(err, ErrNoProviderFactory) {
		t.Fatalf("Provider(general) error = %v, want ErrNoProviderFactory", err)
	}
}

func TestResolver_FactoryError(t *testing.T) {
	boom := errors.New("boom")
	r, err := New(DefaultConfig(), &fakeFactory{err: boom})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = r.Provider(ClassReplicated)
	if !errors.Is(err, boom) {
		t.Fatalf("Provider() error = %v, want it to wrap the factory's", err)
	}
	if !strings.Contains(err.Error(), ClassReplicated) || !strings.Contains(err.Error(), ProviderDRBD) {
		t.Fatalf("Provider() error = %q, want the class and provider named", err)
	}
}

func TestResolver_ConfigIsASnapshot(t *testing.T) {
	cfg := DefaultConfig()
	f := &fakeFactory{}
	r, err := New(cfg, f)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	cfg.DefaultClass = ClassReplicated
	for i := range cfg.Classes {
		cfg.Classes[i].Provider = ProviderDRBD
		cfg.Classes[i].VolumeGroup = "vg9"
	}
	cfg.Classes = nil

	if _, err := r.Provider(""); err != nil {
		t.Fatalf("Provider(\"\") error = %v", err)
	}
	want := factoryCall{provider: ProviderLocal, settings: map[string]string{"volume_group": "platform"}}
	if len(f.calls) != 1 || !reflect.DeepEqual(f.calls[0], want) {
		t.Fatalf("factory calls = %+v, want %+v", f.calls, want)
	}
}

func TestResolver_Defaults(t *testing.T) {
	r, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	d, err := r.Defaults(ClassReplicated)
	if err != nil {
		t.Fatalf("Defaults(replicated) error = %v", err)
	}
	if want := (VolumeDefaults{FSType: "ext4", Replicas: 2}); d != want {
		t.Fatalf("Defaults(replicated) = %+v, want %+v", d, want)
	}
	if _, err := r.Defaults("fast"); !errors.Is(err, ErrUnknownClass) {
		t.Fatalf("Defaults(fast) error = %v, want ErrUnknownClass", err)
	}
}
