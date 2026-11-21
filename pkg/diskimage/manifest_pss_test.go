package diskimage

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
)

// An RSA manifest key behind the platform KMS cannot sign the PS256 the
// manifest asks for: the KMS Sign API carries no RSA-PSS parameters (an SDK
// gap filed upstream), so writeManifest fails with ErrKMSPSSUnsupported
// before it signs or writes anything (Codex P1, #1907).
func TestWriteManifestRefusesAnRSAKMSKey(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "manifest")
	kms := &secureboottest.KMS{Key: key}
	ca := &secureboottest.CA{Certs: map[string]*x509.Certificate{"build/manifest": cert}}
	cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: func() (*iso.KMSClients, error) {
		return &iso.KMSClients{KMS: kms, CA: ca}, nil
	}}
	target, _ := NewTarget("qemu-virt", "")
	image := filepath.Join(t.TempDir(), "img.img")

	path, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(make([]byte, 32)), target, manifestBanks())
	var me *MeasureError
	if !errors.Is(err, secureboot.ErrKMSPSSUnsupported) || !errors.As(err, &me) || me.Step != "opening the manifest key" || path != "" {
		t.Fatalf("path %q, err %v, want ErrKMSPSSUnsupported at opening the manifest key", path, err)
	}
	if kms.LastReq != nil {
		t.Errorf("the KMS got a Sign call %v, want none", kms.LastReq)
	}
	if _, err := os.Stat(ManifestPath(image)); !os.IsNotExist(err) {
		t.Errorf("a refused manifest was written: %v", err)
	}
}
