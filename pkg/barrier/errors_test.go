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

package barrier

import (
	"errors"
	"testing"
)

func TestManagerError_Format(t *testing.T) {
	inner := errors.New("connection refused")
	merr := &ManagerError{Op: "Initialize", Err: inner}

	expected := "barrier: Initialize: connection refused"
	if merr.Error() != expected {
		t.Errorf("expected %q, got %q", expected, merr.Error())
	}
}

func TestManagerError_Unwrap(t *testing.T) {
	inner := errors.New("timeout exceeded")
	merr := &ManagerError{Op: "Unseal", Err: inner}

	if !errors.Is(merr, inner) {
		t.Error("Unwrap should return the inner error")
	}
}

func TestManagerError_WrapsTypedError(t *testing.T) {
	merr := &ManagerError{Op: "Status", Err: ErrSealed}

	if !errors.Is(merr, ErrSealed) {
		t.Error("ManagerError should wrap ErrSealed")
	}
}

func TestConfigError_Format(t *testing.T) {
	cerr := &ConfigError{Field: "SealStrategy", Message: "invalid value"}

	expected := "barrier: config: SealStrategy: invalid value"
	if cerr.Error() != expected {
		t.Errorf("expected %q, got %q", expected, cerr.Error())
	}
}

func TestConfigError_AsConfigError(t *testing.T) {
	var err error = &ConfigError{Field: "ShamirThreshold", Message: "must be positive"}

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatal("errors.As should find ConfigError")
	}
	if configErr.Field != "ShamirThreshold" {
		t.Errorf("expected field ShamirThreshold, got %q", configErr.Field)
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrNotInitialized,
		ErrAlreadyInitialized,
		ErrSealed,
		ErrNotSealed,
		ErrNilSDKClient,
		ErrNilConfig,
		ErrNilContext,
		ErrEmptySecret,
		ErrEmptyShare,
		ErrInvalidThreshold,
	}

	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			if errors.Is(sentinels[i], sentinels[j]) {
				t.Errorf("sentinel errors %q and %q should be distinct",
					sentinels[i], sentinels[j])
			}
		}
	}
}
