package quirks

import (
	"strings"
	"testing"
)

func TestResolveRaspberryPi(t *testing.T) {
	for _, manufacturer := range []string{"Raspberry Pi", "raspberry pi", "RASPBERRY PI"} {
		q := Resolve(manufacturer, "Raspberry Pi 4 Model B")
		if q.Key != "raspberry pi" {
			t.Errorf("Resolve(%q) = %q, want the raspberry pi entry", manufacturer, q.Key)
			continue
		}
		line := strings.Join(q.KernelCmdline, " ")
		if !strings.Contains(line, "console=ttyAMA0,115200") || !strings.Contains(line, "rootwait") {
			t.Errorf("Raspberry Pi cmdline = %q", line)
		}
		if strings.Contains(line, "earlycon=") || strings.Contains(line, "ttyS0") || q.EarlyconSpec != "" {
			t.Errorf("Raspberry Pi cmdline carries x86 console parameters: %q / %q", line, q.EarlyconSpec)
		}
		if q.SOLPort != "ttyAMA0" {
			t.Errorf("SOLPort = %q", q.SOLPort)
		}
		// tty1 last → /dev/console: an operator at the HDMI port sees
		// OpenRC and the firstboot seal.
		assertLastConsoleParam(t, q.KernelCmdline, "console=tty1")
	}
	// A Pi model string alone does not match: the manufacturer is the key.
	if q := Resolve("", "Raspberry Pi 4 Model B"); q.Key != "default" {
		t.Errorf("Resolve(model only) = %q, want default", q.Key)
	}
}
