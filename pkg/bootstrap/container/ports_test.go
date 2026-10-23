// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package container

import (
	"io"
	"net"
	"strconv"
	"testing"
)

// freeTCPPorts returns n pairwise-distinct loopback TCP ports with nothing on
// them. Every listener stays open until all n ports are read, so the kernel
// cannot hand the same port out twice (#936). n <= 0 returns none.
func freeTCPPorts(t *testing.T, n int) []int {
	t.Helper()
	return holdFreePorts(t, n, func() (io.Closer, int, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, 0, err
		}
		return ln, ln.Addr().(*net.TCPAddr).Port, nil
	})
}

// freeUDPPorts is freeTCPPorts for UDP.
func freeUDPPorts(t *testing.T, n int) []int {
	t.Helper()
	return holdFreePorts(t, n, func() (io.Closer, int, error) {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, 0, err
		}
		return conn, conn.LocalAddr().(*net.UDPAddr).Port, nil
	})
}

// holdFreePorts opens n sockets with listen, reads each one's port, and
// closes them all only after the last port is read.
func holdFreePorts(t *testing.T, n int, listen func() (io.Closer, int, error)) []int {
	t.Helper()
	if n <= 0 {
		return nil
	}
	held := make([]io.Closer, 0, n)
	defer func() {
		for _, socket := range held {
			_ = socket.Close()
		}
	}()
	ports := make([]int, 0, n)
	for range n {
		socket, port, err := listen()
		if err != nil {
			t.Fatalf("listen for a free port: %v", err)
		}
		held = append(held, socket)
		ports = append(ports, port)
	}
	return ports
}

func TestFreePorts_AreDistinctAndFree(t *testing.T) {
	const n = 16
	helpers := map[string]struct {
		ports func(*testing.T, int) []int
		bind  func(port int) (io.Closer, error)
	}{
		"tcp": {freeTCPPorts, func(port int) (io.Closer, error) {
			return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		}},
		"udp": {freeUDPPorts, func(port int) (io.Closer, error) {
			return net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		}},
	}
	for name, helper := range helpers {
		t.Run(name, func(t *testing.T) {
			ports := helper.ports(t, n)
			if len(ports) != n {
				t.Fatalf("got %d ports, want %d", len(ports), n)
			}
			seen := make(map[int]bool, n)
			for _, port := range ports {
				if seen[port] {
					t.Fatalf("port %d handed out twice in %v", port, ports)
				}
				seen[port] = true
			}
			// Every socket is closed on return, so each port binds again.
			for _, port := range ports {
				socket, err := helper.bind(port)
				if err != nil {
					t.Fatalf("port %d still held after return: %v", port, err)
				}
				_ = socket.Close()
			}
		})
	}
}

func TestFreePorts_NonPositiveCountReturnsNone(t *testing.T) {
	for _, n := range []int{0, -1} {
		if ports := freeTCPPorts(t, n); ports != nil {
			t.Fatalf("freeTCPPorts(%d) = %v, want none", n, ports)
		}
		if ports := freeUDPPorts(t, n); ports != nil {
			t.Fatalf("freeUDPPorts(%d) = %v, want none", n, ports)
		}
	}
}
