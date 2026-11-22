package diskimage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
