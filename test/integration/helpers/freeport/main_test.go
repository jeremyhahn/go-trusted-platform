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

package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

// The runner's own request: REST, gRPC, QUIC (UDP), MCP and the OVSDB
// manager.
var runnerNetworks = []string{"tcp", "tcp", "udp", "tcp", "tcp"}

func TestRunPrintsOneDistinctPortPerArgument(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out, runnerNetworks); err != nil {
		t.Fatalf("run: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != len(runnerNetworks) {
		t.Fatalf("got %d lines %q, want %d", len(lines), out.String(), len(runnerNetworks))
	}
	seen := make(map[int]bool, len(lines))
	for i, line := range lines {
		port, err := strconv.Atoi(line)
		if err != nil {
			t.Fatalf("line %d %q is not a port: %v", i, line, err)
		}
		if port <= 0 || port > 65535 {
			t.Errorf("line %d: port %d is out of range", i, port)
		}
		if seen[port] {
			t.Errorf("line %d: port %d was printed twice", i, port)
		}
		seen[port] = true
	}
}

func TestChoosePortsReleasesEveryPort(t *testing.T) {
	ports, err := choosePorts(runnerNetworks)
	if err != nil {
		t.Fatalf("choosePorts: %v", err)
	}
	// Each port must be free again once freeport is done, or platformd could
	// not bind it.
	for i, network := range runnerNetworks {
		if err := rebind(network, ports[i]); err != nil {
			t.Errorf("%s port %d is still held: %v", network, ports[i], err)
		}
	}
}

// rebind binds 127.0.0.1:port on network and closes it again.
func rebind(network string, port int) error {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var socket io.Closer
	var err error
	if network == "udp" {
		socket, err = net.ListenPacket("udp4", address)
	} else {
		socket, err = net.Listen("tcp4", address)
	}
	if err != nil {
		return err
	}
	return socket.Close()
}

func TestChoosePortsRejectsAnUnknownNetwork(t *testing.T) {
	ports, err := choosePorts([]string{"tcp", "sctp"})
	var unknown *UnknownNetworkError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want *UnknownNetworkError", err)
	}
	if unknown.Network != "sctp" {
		t.Errorf("Network = %q, want %q", unknown.Network, "sctp")
	}
	if ports != nil {
		t.Errorf("ports = %v, want none on error", ports)
	}
}

func TestRunWritesNothingForAnUnknownNetwork(t *testing.T) {
	var out bytes.Buffer
	err := run(&out, []string{"TCP"})
	var unknown *UnknownNetworkError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want *UnknownNetworkError", err)
	}
	if out.Len() != 0 {
		t.Errorf("wrote %q, want nothing", out.String())
	}
}

func TestChoosePortsRejectsNoArguments(t *testing.T) {
	if _, err := choosePorts(nil); !errors.Is(err, errNoNetworks) {
		t.Fatalf("err = %v, want errNoNetworks", err)
	}
}

func TestBindErrorNamesTheNetworkAndWrapsTheCause(t *testing.T) {
	cause := errors.New("address in use")
	err := &BindError{Network: "udp", Err: cause}
	if !errors.Is(err, cause) {
		t.Error("BindError does not unwrap to its cause")
	}
	if !strings.Contains(err.Error(), "udp") || !strings.Contains(err.Error(), "address in use") {
		t.Errorf("Error() = %q, want the network and the cause", err.Error())
	}
}
