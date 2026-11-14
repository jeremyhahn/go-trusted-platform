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

package commands

import (
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

type bootFIDO2Stub struct{ fido2.Handler }

type bootFIDO2OpenError struct{}

func (bootFIDO2OpenError) Error() string { return "no authenticator" }

func withBootFIDO2Open(t *testing.T, h fido2.Handler, err error) *int {
	t.Helper()
	calls := 0
	orig := newBootFIDO2Handler
	newBootFIDO2Handler = func() (fido2.Handler, error) {
		calls++
		return h, err
	}
	t.Cleanup(func() { newBootFIDO2Handler = orig })
	return &calls
}

// TestBootFIDO2Handler: boot gives the initrd a FIDO2 handler when FIDO2 is
// one of its unlock methods, so a FIDO2 slot can be opened at boot.
func TestBootFIDO2Handler(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("fido2 configured", func(t *testing.T) {
		stub := &bootFIDO2Stub{}
		withBootFIDO2Open(t, stub, nil)
		cfg := &platforminitrd.Config{FallbackMethods: []storageluks.UnlockMethod{storageluks.UnlockTPMPCR, storageluks.UnlockFIDO2}}
		if got := bootFIDO2Handler(cfg, logger); got != fido2.Handler(stub) {
			t.Fatalf("bootFIDO2Handler = %T, want the opened handler", got)
		}
	})

	t.Run("fido2 not configured", func(t *testing.T) {
		calls := withBootFIDO2Open(t, &bootFIDO2Stub{}, nil)
		cfg := &platforminitrd.Config{FallbackMethods: []storageluks.UnlockMethod{storageluks.UnlockTPMPCR, storageluks.UnlockPassword}}
		if got := bootFIDO2Handler(cfg, logger); got != nil {
			t.Fatalf("bootFIDO2Handler = %T, want nil", got)
		}
		if *calls != 0 {
			t.Fatal("opened a FIDO2 handler although FIDO2 is not an unlock method")
		}
	})

	t.Run("open fails", func(t *testing.T) {
		withBootFIDO2Open(t, nil, bootFIDO2OpenError{})
		cfg := &platforminitrd.Config{FallbackMethods: []storageluks.UnlockMethod{storageluks.UnlockFIDO2}}
		if got := bootFIDO2Handler(cfg, logger); got != nil {
			t.Fatalf("bootFIDO2Handler = %T, want nil when the handler cannot be opened", got)
		}
	})
}
