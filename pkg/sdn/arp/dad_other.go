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

package arp

// unsupportedProbeTransport reports that raw ARP probing has no
// implementation on this platform. platformd runs on Linux; this keeps the
// package buildable for developer tooling on other systems without pretending
// a probe succeeded.
type unsupportedProbeTransport struct{}

// NewRawProbeTransport returns a transport whose Open always fails with
// ErrProbeUnsupported.
func NewRawProbeTransport() ProbeTransport { return &unsupportedProbeTransport{} }

// Open always returns ErrProbeUnsupported.
func (t *unsupportedProbeTransport) Open(string) (ProbeSession, error) {
	return nil, ErrProbeUnsupported
}
