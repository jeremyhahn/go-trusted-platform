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

package bmc

import "context"

// vmediaSmcCGI is the legacy Supermicro CGI virtual media backend.
//
// STATUS: documented stub. The wire protocol used by the iKVM HTML5 client
// to mount SMB shares via /cgi/op.cgi and /cgi/url_redirect.cgi has not yet
// been captured in this codebase. The struct exists so the dispatcher in
// vmedia_dispatch.go has a real fall-through path for CIFS specs on
// pre-X12 boards that lack the OEM Redfish CfgCD endpoint and where the
// DCMS license is also missing.
//
// HOW TO FLIP THIS TO A REAL IMPLEMENTATION
//
//  1. Open the iKVM HTML5 console at https://<bmc>/ in Chrome or Firefox.
//  2. Open DevTools → Network, enable preserve log, clear the panel.
//  3. In the iKVM UI: Virtual Media → CD-ROM Image → mount an SMB share
//     with username and password.
//  4. Save the captured network traffic as a HAR file.
//  5. Forward the POST bodies sent to /cgi/op.cgi and /cgi/url_redirect.cgi
//     (form-encoded; opcodes vary by firmware) to the implementer of this
//     file. Replicate the request bodies and the session cookie handshake
//     here, and replace the three method bodies below with real calls.
//
// Until that happens, every method returns ErrVirtualMediaUnsupported so
// the dispatcher correctly walks past this backend and so the test in
// vmedia_smc_cgi_test.go fails loudly the moment a real implementation
// is wired in (the test is the canary that says "flip me when ready").
//
// This backend deliberately advertises CIFS support so the dispatch chain
// records a real attempt against it instead of silently skipping.
type vmediaSmcCGI struct {
	c *redfishClient
}

func newVmediaSmcCGI(c *redfishClient) *vmediaSmcCGI {
	return &vmediaSmcCGI{c: c}
}

// Name returns the stable identifier used in dispatch logs and errors.
func (b *vmediaSmcCGI) Name() string { return "smc-cgi" }

// Supports returns true only for CIFS, which is the historical use case
// for the legacy Supermicro CGI virtual media path. The dispatcher will
// still call Mount on this backend when CIFS is requested; that call
// returns ErrVirtualMediaUnsupported until the wire protocol is captured.
func (b *vmediaSmcCGI) Supports(spec *MediaSpec) bool {
	if spec == nil {
		return false
	}
	return spec.Protocol == MediaProtocolCIFS
}

// Mount returns ErrVirtualMediaUnsupported. See the package doc on this
// type for the HAR-capture procedure that unblocks a real implementation.
func (b *vmediaSmcCGI) Mount(_ context.Context, _ *MediaSpec) error {
	return ErrVirtualMediaUnsupported{
		Backend: b.Name(),
		Vendor:  "Supermicro",
		Reason:  "wire protocol not yet captured — needs HAR/tcpdump from working iKVM HTML5 session",
	}
}

// Unmount returns ErrVirtualMediaUnsupported for the same reason as Mount.
func (b *vmediaSmcCGI) Unmount(_ context.Context) error {
	return ErrVirtualMediaUnsupported{
		Backend: b.Name(),
		Vendor:  "Supermicro",
		Reason:  "wire protocol not yet captured — needs HAR/tcpdump from working iKVM HTML5 session",
	}
}

// Status returns ErrVirtualMediaUnsupported for the same reason as Mount.
func (b *vmediaSmcCGI) Status(_ context.Context) (*VirtualMediaInfo, error) {
	return nil, ErrVirtualMediaUnsupported{
		Backend: b.Name(),
		Vendor:  "Supermicro",
		Reason:  "wire protocol not yet captured — needs HAR/tcpdump from working iKVM HTML5 session",
	}
}
