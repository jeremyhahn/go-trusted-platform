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

// vbootSmcCGI is the legacy Supermicro CGI boot-override backend. It
// targets the same /cgi/op.cgi endpoint the iKVM HTML5 client uses to
// flip BIOS boot device selection without going through Redfish PATCH.
//
// STATUS: documented stub. The wire protocol opcodes for setting boot
// device via the CGI endpoint have not yet been captured in this
// codebase. Until they are, every method returns
// ErrBootOverrideUnsupported so the dispatcher falls through to the
// standard Redfish PATCH path. The struct exists so the dispatch layer
// has a real fall-through target on X10 boards (where Redfish PATCH
// alone gets silently consumed by the BIOS — see virtual_media.go's
// retry loop and pkg/quirks BootOverrideStrategy="smc-cgi").
//
// HOW TO FLIP THIS TO A REAL IMPLEMENTATION
//
//  1. Open the iKVM HTML5 console at https://<bmc>/ in Chrome or Firefox.
//  2. Open DevTools → Network, enable "preserve log", clear the panel.
//  3. In the iKVM UI: Configuration → Boot Order → set "First boot
//     device" to "CD/DVD" (or whichever device the test requires) and
//     click Apply.
//  4. Save the captured network traffic as a HAR file. The relevant
//     POST is to /cgi/op.cgi with form-encoded fields like
//     `op=BIOS_BOOT_INSTANCE_SETTING&BIOS_BOOT_INSTANCE_DEV0=...`.
//     The exact opcode and field names vary by firmware revision.
//  5. Forward the captured HAR to the implementer. Replicate the POST
//     bodies, the session cookie handshake (POST /cgi/login.cgi to get
//     the SID cookie), and the Set-Cookie chain here, then replace
//     SetBootDevice below with real calls.
//
// The mirror test in vboot_smc_cgi_test.go fails the moment a real
// implementation is wired in (it asserts the documented-stub error) so
// you can't accidentally land a half-finished CGI port without
// updating the test in the same change.
type vbootSmcCGI struct {
	c *redfishClient
}

func newVbootSmcCGI(c *redfishClient) *vbootSmcCGI {
	return &vbootSmcCGI{c: c}
}

// Name returns the stable identifier used in dispatch logs and errors.
func (b *vbootSmcCGI) Name() string { return "smc-cgi" }

// SetBootDevice returns ErrBootOverrideUnsupported. See the package doc
// on this type for the HAR-capture procedure that unblocks a real
// implementation.
func (b *vbootSmcCGI) SetBootDevice(_ context.Context, device BootDevice, persistent bool) error {
	return ErrBootOverrideUnsupported{
		Backend: b.Name(),
		Vendor:  "Supermicro",
		Device:  string(device),
		Reason:  "wire protocol not yet captured — needs HAR/tcpdump from working iKVM HTML5 session",
	}
}
