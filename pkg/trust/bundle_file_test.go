// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package trust

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileCABundleProvider_ServesTheBundle(t *testing.T) {
	pemBytes := testCAPEM(t)
	path := filepath.Join(t.TempDir(), "cp-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	provider := NewFileCABundleProvider(path)
	if provider.Path() != path {
		t.Fatalf("Path() = %q, want %q", provider.Path(), path)
	}
	got, err := provider.CABundle(context.Background())
	if err != nil {
		t.Fatalf("CABundle: %v", err)
	}
	if !bytes.Equal(got, pemBytes) {
		t.Fatal("CABundle must return the file's contents")
	}
}

// TestFileCABundleProvider_RereadsOnEveryCall is the reason the provider
// holds a path rather than bytes: a bundle rotated (or delivered late by
// provisioning) takes effect on the next resolution, not at the next
// gatewayd restart.
func TestFileCABundleProvider_RereadsOnEveryCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp-ca.pem")
	first := testCAPEM(t)
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	provider := NewFileCABundleProvider(path)
	ctx := context.Background()
	if _, err := provider.CABundle(ctx); err != nil {
		t.Fatalf("CABundle: %v", err)
	}

	rotated := testCAPEM(t)
	if bytes.Equal(first, rotated) {
		t.Fatal("the test CA generator produced identical bundles")
	}
	if err := os.WriteFile(path, rotated, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := provider.CABundle(ctx)
	if err != nil {
		t.Fatalf("CABundle after rotation: %v", err)
	}
	if !bytes.Equal(got, rotated) {
		t.Fatal("a rotated bundle must be served without reconstructing the provider")
	}
}

func TestFileCABundleProvider_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.pem")
	_, err := NewFileCABundleProvider(path).CABundle(context.Background())

	var readErr *ErrCAFileRead
	if !errors.As(err, &readErr) {
		t.Fatalf("err = %v, want *ErrCAFileRead", err)
	}
	if readErr.Path != path {
		t.Fatalf("Path = %q, want %q", readErr.Path, path)
	}
}

func TestFileCABundleProvider_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewFileCABundleProvider(path).CABundle(context.Background())
	if !errors.Is(err, ErrCABundleEmpty{}) {
		t.Fatalf("err = %v, want ErrCABundleEmpty", err)
	}
}

func TestFileCABundleProvider_UnsetPath(t *testing.T) {
	_, err := NewFileCABundleProvider("").CABundle(context.Background())
	var unset *ErrCABundleFileUnset
	if !errors.As(err, &unset) {
		t.Fatalf("err = %v, want *ErrCABundleFileUnset", err)
	}
}

// TestFileCABundleProvider_ResolvesTheInternalClass wires the provider the
// way gatewayd does — the internal class on platform-ca, its bundle a file
// on disk — and asserts the class resolves. Off the control plane this is
// the ONLY way the internal class can resolve at all.
func TestFileCABundleProvider_ResolvesTheInternalClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp-ca.pem")
	if err := os.WriteFile(path, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg, WithPlatformCA(NewFileCABundleProvider(path)))

	tlsCfg, err := resolver.TLSConfig(context.Background(), ClassInternal, "cp.example.internal:9443")
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("the internal class must resolve to a verification pool")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Fatal("the internal class always verifies")
	}
}
