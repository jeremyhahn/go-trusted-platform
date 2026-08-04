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

//go:build !linux

package ipxe

import (
	"net"
	"time"
)

// ServerRawConn is not supported on non-Linux platforms.
type ServerRawConn struct{}

// NewServerRawConn returns an error on non-Linux platforms.
func NewServerRawConn(iface string, serverIP net.IP, port int) (*ServerRawConn, error) {
	return nil, &MessageError{Msg: "raw sockets are only supported on Linux"}
}

// ReadFrom is not implemented on non-Linux platforms.
func (c *ServerRawConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, &MessageError{Msg: "not implemented"}
}

// WriteTo is not implemented on non-Linux platforms.
func (c *ServerRawConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, &MessageError{Msg: "not implemented"}
}

// Close is not implemented on non-Linux platforms.
func (c *ServerRawConn) Close() error {
	return &MessageError{Msg: "not implemented"}
}

// LocalAddr is not implemented on non-Linux platforms.
func (c *ServerRawConn) LocalAddr() net.Addr {
	return nil
}

// SetDeadline is not implemented on non-Linux platforms.
func (c *ServerRawConn) SetDeadline(t time.Time) error {
	return &MessageError{Msg: "not implemented"}
}

// SetReadDeadline is not implemented on non-Linux platforms.
func (c *ServerRawConn) SetReadDeadline(t time.Time) error {
	return &MessageError{Msg: "not implemented"}
}

// SetWriteDeadline is not implemented on non-Linux platforms.
func (c *ServerRawConn) SetWriteDeadline(t time.Time) error {
	return &MessageError{Msg: "not implemented"}
}
