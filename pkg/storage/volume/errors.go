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

import "errors"

var (
	// ErrNilConfig is returned for a nil *Config.
	ErrNilConfig = errors.New("volume: nil config")

	// ErrNoClasses is returned when a Config defines no storage class.
	ErrNoClasses = errors.New("volume: no storage classes configured")

	// ErrClassNameRequired is returned for a storage class without a name.
	ErrClassNameRequired = errors.New("volume: storage class name is required")

	// ErrProviderRequired is returned for a storage class without a provider.
	ErrProviderRequired = errors.New("volume: storage class provider is required")

	// ErrUnknownProvider is returned for a provider name this package does
	// not know.
	ErrUnknownProvider = errors.New("volume: unknown provider")

	// ErrDuplicateClass is returned when two storage classes share a name.
	ErrDuplicateClass = errors.New("volume: duplicate storage class")

	// ErrUnknownClass is returned when a requested class is not configured.
	ErrUnknownClass = errors.New("volume: unknown storage class")

	// ErrUnknownDefaultClass is returned when DefaultClass names a class
	// that is not configured.
	ErrUnknownDefaultClass = errors.New("volume: default class is not configured")

	// ErrNoDefaultClass is returned when the default class is asked for
	// and none is set.
	ErrNoDefaultClass = errors.New("volume: no default storage class")

	// ErrInvalidReplicas is returned for a negative replica count.
	ErrInvalidReplicas = errors.New("volume: replicas must not be negative")

	// ErrSettingConflict is returned when Settings repeats a typed field's
	// key with a different value.
	ErrSettingConflict = errors.New("volume: setting conflicts with a typed field")

	// ErrBlockSettingOnObjectClass is returned when an object class sets a
	// field that only block providers take.
	ErrBlockSettingOnObjectClass = errors.New("volume: block setting on an object storage class")

	// ErrObjectClassNotBlock is returned when a block provider is asked for
	// an object storage class.
	ErrObjectClassNotBlock = errors.New("volume: object storage class has no block provider")

	// ErrNoProviderFactory is returned when no Factory is supplied to
	// construct block providers.
	ErrNoProviderFactory = errors.New("volume: no provider factory")
)
