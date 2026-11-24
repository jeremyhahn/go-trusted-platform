package diskimage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// The rpi5 control-plane template is shipped (experimental), so --model rpi5
// --role control-plane resolves to it instead of being refused (#1701).
func TestRoleTemplate_RPi5ControlPlane(t *testing.T) {
	t.Chdir(repoRoot)
	got, err := roleTemplate("rpi", "rpi5", "control-plane", "")
	if err != nil {
		t.Fatalf("roleTemplate(rpi, rpi5, control-plane): %v", err)
	}
	want := filepath.Join("configs", "platform", "templates", "dedicated", "raspberrypi", "rpi5", "control-plane.yaml")
	if got != want {
		t.Errorf("roleTemplate(rpi, rpi5, control-plane) = %q, want %q", got, want)
	}
}

func TestRoleTemplate_UnderPlatformConfigDir(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "templates", "dedicated", "raspberrypi", "rpi5", "control-plane.yaml")
	if err := os.MkdirAll(filepath.Dir(want), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLATFORM_CONFIG_DIR", dir)
	got, err := roleTemplate("rpi", "rpi5", "control-plane", "")
	if err != nil {
		t.Fatalf("roleTemplate(rpi, rpi5, control-plane): %v", err)
	}
	if got != want {
		t.Errorf("roleTemplate(rpi, rpi5, control-plane) = %q, want %q", got, want)
	}

	t.Setenv("PLATFORM_CONFIG_DIR", t.TempDir())
	_, err = roleTemplate("rpi", "rpi5", "control-plane", "")
	var refused ErrRoleTemplate
	if !errors.As(err, &refused) {
		t.Errorf("roleTemplate with an empty PLATFORM_CONFIG_DIR = %v, want ErrRoleTemplate", err)
	}
}

func writePlatformTemplate(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A set PLATFORM_CONFIG_DIR must hold the disk-image media template: the
// in-tree public templates are never a fallback, its templates are the ones
// selected, and an explicit --platform-config bypasses it.
func TestISOConfig_PlatformConfigDir(t *testing.T) {
	t.Run("empty configured root is refused even with in-tree templates", func(t *testing.T) {
		t.Chdir(repoRoot)
		dir := t.TempDir()
		t.Setenv("PLATFORM_CONFIG_DIR", dir)
		for _, target := range []string{"rpi", ""} {
			_, err := (&mediaFlags{}).isoConfig(target, "")
			var missing *cli.ErrPlatformTemplateMissing
			if !errors.As(err, &missing) {
				t.Fatalf("isoConfig(%q) with an empty PLATFORM_CONFIG_DIR = %v, want ErrPlatformTemplateMissing", target, err)
			}
			want := filepath.Join("single-node", "default.yaml")
			if !strings.HasPrefix(missing.Path, dir+string(filepath.Separator)) || !strings.HasSuffix(missing.Path, want) {
				t.Errorf("isoConfig(%q) missing path = %q, want under %q ending in %q", target, missing.Path, dir, want)
			}
		}
	})

	t.Run("configured root template is selected", func(t *testing.T) {
		t.Chdir(repoRoot)
		dir := t.TempDir()
		single := filepath.Join(dir, "templates", "single-node", "default.yaml")
		rpi4 := filepath.Join(dir, "templates", "single-node", "raspberrypi", "rpi4", "default.yaml")
		writePlatformTemplate(t, single)
		writePlatformTemplate(t, rpi4)
		t.Setenv("PLATFORM_CONFIG_DIR", dir)
		for target, want := range map[string]string{"qemu-virt": single, "rpi": rpi4} {
			cfg, err := (&mediaFlags{}).isoConfig(target, "")
			if err != nil {
				t.Fatalf("isoConfig(%q): %v", target, err)
			}
			if cfg.PlatformConfigFile != want {
				t.Errorf("isoConfig(%q) PlatformConfigFile = %q, want %q", target, cfg.PlatformConfigFile, want)
			}
		}
	})

	t.Run("explicit platform config bypasses the configured root", func(t *testing.T) {
		t.Chdir(repoRoot)
		explicit := filepath.Join(t.TempDir(), "platform.yaml")
		writePlatformTemplate(t, explicit)
		t.Setenv("PLATFORM_CONFIG_DIR", t.TempDir())
		cfg, err := (&mediaFlags{platformConfig: explicit}).isoConfig("rpi", "")
		if err != nil {
			t.Fatalf("isoConfig with --platform-config: %v", err)
		}
		if cfg.PlatformConfigFile != explicit {
			t.Errorf("PlatformConfigFile = %q, want %q", cfg.PlatformConfigFile, explicit)
		}
	})
}
