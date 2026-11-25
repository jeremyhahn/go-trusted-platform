package diskimage

import (
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
