package diskimage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

const (
	usableShadow = "root:$6$salt$hash:19000:0:::::\ndaemon:*:19000:0:::::\n"
	lockedShadow = "root:!:19000:0:::::\ndaemon:*:19000:0:::::\n"
)

func TestPackRootRefusesAUsableHashAndPacksALockedRoot(t *testing.T) {
	rec := newDisklessRunner()
	tree := map[string]string{"sbin/init": "x", "usr/bin/platformd": "x", "etc/fstab": "x"}

	tree["etc/shadow"] = usableShadow
	err := packRoot(context.Background(), rec.run, writeTree(t, tree), filepath.Join(t.TempDir(), "rootfs"), testEpoch)
	var found DisklessRootCredentialError
	if !errors.As(err, &found) || found.Account != "root" || found.Path != "etc/shadow" {
		t.Fatalf("err = %v, want a DisklessRootCredentialError for root in etc/shadow", err)
	}
	if slices.ContainsFunc(rec.calls, func(c string) bool { return strings.HasPrefix(c, "mksquashfs") }) {
		t.Error("a root with a usable password hash was packed")
	}

	tree["etc/shadow"] = lockedShadow
	if err := packRoot(context.Background(), rec.run, writeTree(t, tree), filepath.Join(t.TempDir(), "rootfs"), testEpoch); err != nil {
		t.Fatalf("a locked root was refused: %v", err)
	}
}

func TestRefuseRootCredentials(t *testing.T) {
	cases := map[string]struct {
		files   map[string]string
		account string
	}{
		"no shadow file":          {map[string]string{"etc/hostname": "n"}, ""},
		"locked and starred":      {map[string]string{"etc/shadow": lockedShadow}, ""},
		"hash":                    {map[string]string{"etc/shadow": usableShadow}, "root"},
		"empty password":          {map[string]string{"etc/shadow": "root::19000:0:::::\n"}, "root"},
		"hash only in the backup": {map[string]string{"etc/shadow": lockedShadow, "etc/shadow-": "admin:$6$x$y:1::::::\n"}, "admin"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := refuseRootCredentials(writeTree(t, tc.files))
			if tc.account == "" {
				if err != nil {
					t.Fatalf("err = %v, want none", err)
				}
				return
			}
			var found DisklessRootCredentialError
			if !errors.As(err, &found) || found.Account != tc.account {
				t.Fatalf("err = %v, want a DisklessRootCredentialError for %s", err, tc.account)
			}
		})
	}

	if err := refuseRootCredentials(writeTree(t, map[string]string{"etc/shadow/x": "a"})); err == nil {
		t.Error("an unreadable shadow file was accepted")
	}
}

func TestLockRootAccounts(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/shadow":  usableShadow + "bin:!!:1::::::\n",
		"etc/shadow-": "root::19000:0:::::\n",
	})
	if err := lockRootAccounts(root); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{
		"etc/shadow":  lockedShadow + "bin:!!:1::::::\n",
		"etc/shadow-": "root:!:19000:0:::::\n",
	} {
		if got, err := os.ReadFile(filepath.Join(root, rel)); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", rel, got, err, want)
		}
	}
	if err := refuseRootCredentials(root); err != nil {
		t.Errorf("a locked root is still refused: %v", err)
	}

	if err := lockRootAccounts(writeTree(t, map[string]string{"etc/shadow/x": "a"})); err == nil {
		t.Error("an unreadable shadow file was accepted")
	}
	if err := lockRootAccounts(writeTree(t, map[string]string{"etc/hostname": "n"})); err != nil {
		t.Errorf("a root without a shadow file failed: %v", err)
	}
}

func TestGenerateDisklessRootLocksTheInstallerPassword(t *testing.T) {
	rec := newDisklessRunner()
	rec.tree["etc/shadow"] = usableShadow
	opts := disklessOptions(t, rec, &fakeAssemble{parts: 2})
	if _, err := GenerateDisklessRoot(context.Background(), opts); err != nil {
		t.Fatalf("GenerateDisklessRoot: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(opts.WorkDir, "root", "etc", "shadow"))
	if err != nil || string(got) != lockedShadow {
		t.Errorf("packed shadow = %q, %v; want %q", got, err, lockedShadow)
	}
}

func TestGenerateDisklessRootRefusesDebug(t *testing.T) {
	rec := newDisklessRunner()
	opts := disklessOptions(t, rec, &fakeAssemble{parts: 2})
	opts.Config = &installer.Config{Debug: true}
	_, err := GenerateDisklessRoot(context.Background(), opts)
	var in DisklessRootInputError
	if !errors.As(err, &in) || in.Field != "debug" {
		t.Fatalf("err = %v, want a debug DisklessRootInputError", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("tools ran for a refused build: %v", rec.calls)
	}
}

func TestDisklessRootCredentialErrorNamesTheAccount(t *testing.T) {
	want := "diskless root: /etc/shadow: account root has a usable password; the root is public"
	if got := (DisklessRootCredentialError{Path: "etc/shadow", Account: "root"}).Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
