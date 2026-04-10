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

package deployer

import (
	"errors"
	"log/slog"
	"os"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewDeployer_Linux(t *testing.T) {
	d, err := NewDeployer(TargetLinux, testLogger())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if d == nil {
		t.Fatal("expected deployer, got nil")
	}
	if _, ok := d.(*LinuxDeployer); !ok {
		t.Fatalf("expected *LinuxDeployer, got %T", d)
	}
}

func TestNewDeployer_Cisco(t *testing.T) {
	d, err := NewDeployer(TargetCisco, testLogger())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if d == nil {
		t.Fatal("expected deployer, got nil")
	}
	if _, ok := d.(*CiscoDeployer); !ok {
		t.Fatalf("expected *CiscoDeployer, got %T", d)
	}
}

func TestNewDeployer_Unknown(t *testing.T) {
	_, err := NewDeployer(DeployTarget("solaris"), testLogger())
	if err == nil {
		t.Fatal("expected error for unknown target")
	}
	var target ErrUnknownTarget
	if !errors.As(err, &target) {
		t.Errorf("expected ErrUnknownTarget, got %T: %v", err, err)
	}
}
