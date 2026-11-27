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

import "fmt"

// Provider is a block volume provider: the same two operations as
// nbd.VolumeProvider.
type Provider interface {
	// Create makes identity's volume at size bytes if it does not exist.
	Create(identity string, size int64) error

	// Attach returns the path of identity's volume: a regular file or a
	// block device the caller opens.
	Attach(identity string) (string, error)
}

// Factory constructs a block Provider from a provider name and its
// construction settings. It is supplied by the go-quicbaas SDK's volumes
// surface once it has one; this package constructs nothing itself.
type Factory interface {
	NewProvider(provider string, settings map[string]string) (Provider, error)
}

// Resolver resolves storage classes to block providers through a Factory.
type Resolver struct {
	cfg     *Config
	factory Factory
}

// New validates cfg and returns a Resolver over a copy of it. A nil
// factory is allowed: every Provider call then answers
// ErrNoProviderFactory.
func New(cfg *Config, factory Factory) (*Resolver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Resolver{cfg: cfg.Clone(), factory: factory}, nil
}

// Provider returns the block provider serving class; an empty class is the
// default class.
func (r *Resolver) Provider(class string) (Provider, error) {
	sc, err := r.cfg.Class(class)
	if err != nil {
		return nil, err
	}
	if sc.IsObjectStore() {
		return nil, fmt.Errorf("storage class %q: %w", sc.Name, ErrObjectClassNotBlock)
	}
	if r.factory == nil {
		return nil, fmt.Errorf("storage class %q: %w", sc.Name, ErrNoProviderFactory)
	}
	p, err := r.factory.NewProvider(sc.Provider, sc.ToSettings())
	if err != nil {
		return nil, fmt.Errorf("storage class %q provider %q: %w", sc.Name, sc.Provider, err)
	}
	return p, nil
}

// Defaults returns the per-volume defaults of class; an empty class is the
// default class.
func (r *Resolver) Defaults(class string) (VolumeDefaults, error) {
	sc, err := r.cfg.Class(class)
	if err != nil {
		return VolumeDefaults{}, err
	}
	return sc.Defaults, nil
}
