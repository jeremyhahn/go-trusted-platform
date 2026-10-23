package diskimage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// referencedConfig is a platform config whose every secret is a reference.
const referencedConfig = `hostname: node-1
os:
  root-password: kms://os/root-password
platform:
  so-pin: kms://platform/so-pin
  user-pin: env://PLATFORM_USER_PIN
bmc:
  user: admin
  password: kms://bmc/password
switches:
  - user: admin
    password: file:///run/secrets/switch-0
disk:
  encryption:
    password: kms://disk/password
`

func TestPackRootRefusesAPlaintextConfigSecretAndPacksAReferencedOne(t *testing.T) {
	rec := newDisklessRunner()
	tree := map[string]string{"sbin/init": "x", "usr/bin/platformd": "x", "etc/fstab": "x"}

	tree[disklessPlatformConfig] = "os:\n  root-password: hunter2\n"
	err := packRoot(context.Background(), rec.run, writeTree(t, tree), filepath.Join(t.TempDir(), "rootfs"), testEpoch)
	var found DisklessRootConfigSecretError
	if !errors.As(err, &found) || !slices.Equal(found.Fields, []string{"os.root-password"}) {
		t.Fatalf("err = %v, want a DisklessRootConfigSecretError for os.root-password", err)
	}
	if slices.ContainsFunc(rec.calls, func(c string) bool { return strings.HasPrefix(c, "mksquashfs") }) {
		t.Error("a root with a plaintext config secret was packed")
	}

	tree[disklessPlatformConfig] = referencedConfig
	root := writeTree(t, tree)
	if err := packRoot(context.Background(), rec.run, root, filepath.Join(t.TempDir(), "rootfs"), testEpoch); err != nil {
		t.Fatalf("a config holding only references was refused: %v", err)
	}
	if !slices.ContainsFunc(rec.calls, func(c string) bool { return strings.HasPrefix(c, "mksquashfs") }) {
		t.Error("a config holding only references was not packed")
	}
	if got, err := os.ReadFile(filepath.Join(root, disklessPlatformConfig)); err != nil || string(got) != referencedConfig {
		t.Errorf("packed config = %q, %v; want it unchanged", got, err)
	}
}

func TestRefuseRootConfigSecrets(t *testing.T) {
	cases := map[string]struct {
		config string
		fields []string
	}{
		"root password":          {"os:\n  root-password: hunter2\n", []string{"os.root-password"}},
		"BMC password":           {"bmc:\n  password: calvin\n", []string{"bmc.password"}},
		"BMC IPMI key":           {"bmc:\n  encryption-key: 0011aabb\n", []string{"bmc.encryption-key"}},
		"PKCS#11 PINs":           {"platform:\n  so-pin: \"12345678\"\n  user-pin: \"123456\"\n", []string{"platform.so-pin", "platform.user-pin"}},
		"switch password":        {"switches:\n  - password: kms://s0\n  - password: admin\n", []string{"switches[1].password"}},
		"disk encryption":        {"disk:\n  encryption:\n    password: p\n    passphrase: q\n", []string{"disk.encryption.password", "disk.encryption.passphrase"}},
		"every secret reference": {referencedConfig, nil},
		"no secret fields":       {"hostname: node-1\ndomain: example.com\n", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := refuseRootConfigSecrets(writeTree(t, map[string]string{disklessPlatformConfig: tc.config}))
			if tc.fields == nil {
				if err != nil {
					t.Fatalf("err = %v, want none", err)
				}
				return
			}
			var found DisklessRootConfigSecretError
			if !errors.As(err, &found) || !slices.Equal(found.Fields, tc.fields) || found.Path != disklessPlatformConfig {
				t.Fatalf("err = %v, want a DisklessRootConfigSecretError for %q", err, tc.fields)
			}
		})
	}

	if err := refuseRootConfigSecrets(writeTree(t, map[string]string{"etc/hostname": "n"})); err != nil {
		t.Errorf("a root without a platform config was refused: %v", err)
	}
}

func TestRefuseRootConfigSecretsFailsOnAnUnreadableConfig(t *testing.T) {
	if err := refuseRootConfigSecrets(writeTree(t, map[string]string{disklessPlatformConfig + "/x": "a"})); err == nil {
		t.Error("an unreadable platform config was accepted")
	}

	err := refuseRootConfigSecrets(writeTree(t, map[string]string{disklessPlatformConfig: "bmc: [unclosed\n"}))
	var parseErr bootstrap.ErrSecretDocumentParse
	if !errors.As(err, &parseErr) {
		t.Errorf("err = %v, want a bootstrap.ErrSecretDocumentParse for a malformed config", err)
	}
}

func TestDisklessRootConfigSecretErrorNamesTheFields(t *testing.T) {
	err := DisklessRootConfigSecretError{Path: disklessPlatformConfig, Fields: []string{"bmc.password", "platform.so-pin"}}
	want := "diskless root: /etc/trusted-platform/config.yaml: bmc.password, platform.so-pin hold plaintext secrets; " +
		"use a secret reference (kms://, env://, file:// ...); the root is public"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
