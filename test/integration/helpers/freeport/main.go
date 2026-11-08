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

// Command freeport prints free loopback ports for the integration runner.
//
// Every act_runner job container runs with `network: host`, so two
// Integration jobs on one host share a network namespace and cannot both
// listen on fixed ports (#997). The runner calls freeport once with one
// argument per port it needs, `tcp` or `udp`. freeport binds 127.0.0.1:0 for
// each argument and holds every socket open until all of them are bound, so
// the kernel never hands out the same port twice, then prints the ports one
// per line in argument order. It uses only the standard library: the
// devcontainer has Go but no python3.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

// errNoNetworks is returned when freeport is called without arguments.
var errNoNetworks = errors.New(`freeport: no ports requested; pass "tcp" or "udp" once per port`)

// UnknownNetworkError reports an argument that is neither "tcp" nor "udp".
type UnknownNetworkError struct {
	Network string
}

func (e *UnknownNetworkError) Error() string {
	return "freeport: unknown network " + strconv.Quote(e.Network) + `, want "tcp" or "udp"`
}

// BindError reports a loopback socket the kernel would not bind.
type BindError struct {
	Network string
	Err     error
}

func (e *BindError) Error() string {
	return "freeport: bind " + e.Network + " 127.0.0.1:0: " + e.Err.Error()
}

func (e *BindError) Unwrap() error { return e.Err }

// binder binds one loopback socket and returns its port and the socket.
type binder func() (int, io.Closer, error)

var binders = map[string]binder{
	"tcp": bindTCP,
	"udp": bindUDP,
}

func bindTCP() (int, io.Closer, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, nil, &BindError{Network: "tcp", Err: err}
	}
	return listener.Addr().(*net.TCPAddr).Port, listener, nil
}

func bindUDP() (int, io.Closer, error) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return 0, nil, &BindError{Network: "udp", Err: err}
	}
	return conn.LocalAddr().(*net.UDPAddr).Port, conn, nil
}

// choosePorts returns one free port per network, all distinct. TCP and UDP
// have separate port spaces, so a UDP port may equal a TCP port already
// chosen; that socket stays held and the bind is retried, which keeps every
// printed port distinct whatever the mix of networks.
func choosePorts(networks []string) (ports []int, err error) {
	if len(networks) == 0 {
		return nil, errNoNetworks
	}
	var held []io.Closer
	defer func() {
		for _, socket := range held {
			err = errors.Join(err, socket.Close())
		}
	}()
	chosen := make(map[int]bool, len(networks))
	for _, network := range networks {
		bind, ok := binders[network]
		if !ok {
			return nil, &UnknownNetworkError{Network: network}
		}
		for {
			port, socket, bindErr := bind()
			if bindErr != nil {
				return nil, bindErr
			}
			held = append(held, socket)
			if !chosen[port] {
				chosen[port] = true
				ports = append(ports, port)
				break
			}
		}
	}
	return ports, nil
}

// run writes one port per line to out, one for each network in args.
func run(out io.Writer, args []string) error {
	ports, err := choosePorts(args)
	if err != nil {
		return err
	}
	for _, port := range ports {
		if _, err := fmt.Fprintln(out, port); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
