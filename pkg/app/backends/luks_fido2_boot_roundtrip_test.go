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

package backends

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// hmacSecretAuthenticator models a CTAP2 hmac-secret authenticator: the
// secret depends on the credential, the salt, the relying party and whether
// user verification was asked, so a boot that rebuilds any of them
// differently derives a different key.
type hmacSecretAuthenticator struct {
	fido2.Handler

	credentialID []byte
	seed         []byte
	calls        int
}

func (a *hmacSecretAuthenticator) UnlockWithKey(cfg *fido2.AuthenticationConfig) ([]byte, error) {
	a.calls++
	if string(cfg.CredentialID) != string(a.credentialID) || len(cfg.Salt) == 0 {
		return nil, &MessageError{Msg: "authenticator: unknown credential or no salt"}
	}
	h := sha256.New()
	h.Write(a.seed)
	h.Write(cfg.CredentialID)
	h.Write(cfg.Salt)
	h.Write([]byte(cfg.RelyingPartyID))
	if cfg.RequireUserVerification {
		h.Write([]byte{1})
	}
	return h.Sum(nil), nil
}

// keyCheckingLUKS is the boot LUKS handler with Open replaced by a check that
// the key opens the keyslot boot chose: device-mapper is not available in a
// unit test, the header and the token area are real.
type keyCheckingLUKS struct {
	*storageluks.CryptsetupHandler
	openedSlot int
}

func (l *keyCheckingLUKS) Open(_ context.Context, device, _ string, key []byte, opts *storageluks.OpenOptions) error {
	if opts == nil || opts.KeySlot == nil {
		return &MessageError{Msg: "boot opened without naming a keyslot"}
	}
	if err := luks2.TestKey(device, key); err != nil {
		return err
	}
	l.openedSlot = *opts.KeySlot
	return nil
}

// TestLUKSFIDO2EnrollmentUnlocksAtBoot is the enrollment-to-boot round trip
// for a FIDO2 slot enrolled through platformd: the slot EnrollFIDO2 writes
// is found and opened by the initrd FIDO2 strategy from its header token,
// even though the boot configuration numbers its FIDO2 slot by position.
func TestLUKSFIDO2EnrollmentUnlocksAtBoot(t *testing.T) {
	ctx := context.Background()
	device := newLUKSImage(t)
	auth := &hmacSecretAuthenticator{
		credentialID: []byte("platformd-enrolled-credential-01"),
		seed:         []byte("authenticator-secret"),
	}
	handler, err := NewLUKSFIDO2Handler(nil, auth, "")
	if err != nil {
		t.Fatalf("NewLUKSFIDO2Handler: %v", err)
	}
	b := newTestLUKSBackend(WithLUKSFIDO2Handler(handler))

	// A second passphrase first, so the FIDO2 slot is not the one the
	// boot configuration's position would name.
	if _, err := b.EnrollPassphrase(ctx, &daemon.LUKSEnrollPassphraseRequest{
		Device: device, ExistingPassphrase: testLUKSPassphrase, NewPassphrase: "second-passphrase",
	}); err != nil {
		t.Fatalf("EnrollPassphrase: %v", err)
	}
	res, err := b.EnrollFIDO2(ctx, &daemon.LUKSEnrollFIDO2Request{
		Device:             device,
		ExistingPassphrase: testLUKSPassphrase,
		CredentialID:       hex.EncodeToString(auth.credentialID),
		RequireUV:          true,
	})
	if err != nil {
		t.Fatalf("EnrollFIDO2: %v", err)
	}

	cryptsetup, err := storageluks.NewCryptsetupHandlerImpl(storageluks.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("NewCryptsetupHandlerImpl: %v", err)
	}
	bootLUKS := &keyCheckingLUKS{CryptsetupHandler: cryptsetup, openedSlot: -1}
	platform := &initrd.Platform{
		LUKS:   bootLUKS,
		FIDO2:  auth,
		Config: &initrd.Config{RootDevice: device},
	}
	// The boot configuration numbers slots by fallback position
	// (tpm-pcr, fido2, password): its FIDO2 slot is 1.
	volume := &storageluks.VolumeConfig{
		DevicePath:  device,
		MappingName: "root",
		KeySlots: []storageluks.KeySlot{
			{Index: 0, Type: storageluks.UnlockTPMPCR},
			{Index: 1, Type: storageluks.UnlockFIDO2},
			{Index: 2, Type: storageluks.UnlockPassword},
		},
	}
	strategy := initrd.NewFIDO2Strategy(platform, logging.DefaultLogger())
	if !strategy.CanUnlock(ctx, volume) {
		t.Fatal("CanUnlock = false for a volume with a FIDO2 token")
	}
	if err := strategy.Unlock(ctx, volume); err != nil {
		t.Fatalf("boot Unlock of the platformd-enrolled FIDO2 slot: %v", err)
	}
	if bootLUKS.openedSlot != int(res.Slot) {
		t.Fatalf("boot opened slot %d, want the enrolled slot %d", bootLUKS.openedSlot, res.Slot)
	}
}
