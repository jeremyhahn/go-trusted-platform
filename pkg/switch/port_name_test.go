package switchmgmt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// invalidPortNames are names that are not one interface identifier: CLI
// separators, pipes, control characters, shell metacharacters, spaces and
// names without a letter prefix or a port number.
var invalidPortNames = []string{
	"",
	"Eth1/3; show running-config",
	"Eth1/3 | include x",
	"Eth1/3\nshow running-config",
	"Eth1/3\r",
	"Eth1/3\x00",
	"Eth1/3\t",
	"Eth 1/3",
	"Eth1/3&&x",
	"$(reboot)",
	"`Eth1/3`",
	"Eth1/3>x",
	"1/3",
	"Eth",
	strings.Repeat("a", 60) + "1/1",
}

func TestValidatePortName(t *testing.T) {
	valid := []string{
		"Eth1/3",
		"Ethernet1/49/1",
		"Eth101/1/1",
		"Eth1/1.100",
		"port-channel10",
		"Po10",
		"mgmt0",
		"eth1",
	}
	for _, name := range valid {
		if err := ValidatePortName(name); err != nil {
			t.Errorf("ValidatePortName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range invalidPortNames {
		err := ValidatePortName(name)
		var cfgErr ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "port" {
			t.Errorf("ValidatePortName(%q) = %v, want ErrInvalidConfig{Field: port}", name, err)
		}
	}
}

func TestSSHManager_RejectsUnsafePortNameBeforeSSH(t *testing.T) {
	ctx := context.Background()
	ops := map[string]func(m *sshManager, port string) error{
		"GetPortVLAN": func(m *sshManager, port string) error {
			_, err := m.GetPortVLAN(ctx, port)
			return err
		},
		"GetPortStatus": func(m *sshManager, port string) error {
			_, err := m.GetPortStatus(ctx, port)
			return err
		},
		"SetPortVLAN": func(m *sshManager, port string) error {
			return m.SetPortVLAN(ctx, port, 100)
		},
		"EnablePort": func(m *sshManager, port string) error {
			return m.EnablePort(ctx, port)
		},
		"DisablePort": func(m *sshManager, port string) error {
			return m.DisablePort(ctx, port)
		},
	}
	for opName, op := range ops {
		for _, name := range invalidPortNames {
			mock := newMockSSHExecutor()
			m := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
			err := op(m, name)
			var cfgErr ErrInvalidConfig
			if !errors.As(err, &cfgErr) || cfgErr.Field != "port" {
				t.Errorf("%s(%q) error = %v, want ErrInvalidConfig{Field: port}", opName, name, err)
			}
			if len(mock.commands) != 0 {
				t.Errorf("%s(%q) sent %d SSH commands, want 0", opName, name, len(mock.commands))
			}
		}
	}
}
