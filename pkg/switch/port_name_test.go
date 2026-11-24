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

func TestCanonicalPortName(t *testing.T) {
	cases := map[string]string{
		"Ethernet1/3":    "eth1/3",
		"Eth1/3":         "eth1/3",
		"ET1/3":          "eth1/3",
		"Ethernet1/49/1": "eth1/49/1",
		"Eth1/1.100":     "eth1/1.100",
		"port-channel10": "po10",
		"Po10":           "po10",
		"mgmt0":          "mgmt0",
		"MGMT0":          "mgmt0",
	}
	for in, want := range cases {
		if got := canonicalPortName(in); got != want {
			t.Errorf("canonicalPortName(%q) = %q, want %q", in, got, want)
		}
	}
	for _, pair := range [][2]string{{"Eth1/3", "Eth1/30"}, {"Eth10", "Po10"}} {
		if samePort(pair[0], pair[1]) {
			t.Errorf("samePort(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}
