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

package ipxe

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestAddPXEOptions_EchoesPXEClientVendorClass verifies that the DHCP reply to
// a (non-iPXE) UEFI PXE client carries option 60 = "PXEClient". UEFI PXE
// firmware rejects offers that omit this and re-DISCOVERs forever (PXE-E18),
// so this is a regression guard for UEFI PXE boot.
func TestAddPXEOptions_EchoesPXEClientVendorClass(t *testing.T) {
	const archUEFIx64 = 0x0007

	srv, err := NewDHCPServer(&DHCPConfig{
		ServerIP:           net.ParseIP("198.18.1.91"),
		RangeStart:         net.ParseIP("198.18.1.220"),
		RangeEnd:           net.ParseIP("198.18.1.230"),
		TFTPServerIP:       net.ParseIP("198.18.1.91"),
		BootFilenameByArch: DefaultBootFilenameByArch(),
		IPXEScript:         "http://198.18.1.91:8080/boot.ipxe",
	}, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("NewDHCPServer: %v", err)
	}

	// Non-iPXE UEFI firmware: must receive option 60 = "PXEClient" + an EFI
	// boot filename.
	reply, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	srv.addPXEOptions(reply, archUEFIx64, false)

	if got := reply.ClassIdentifier(); got != vendorClassPXEClient {
		t.Errorf("option 60 ClassIdentifier = %q, want %q", got, vendorClassPXEClient)
	}
	if reply.BootFileName == "" {
		t.Error("expected a boot filename for the UEFI PXE client, got empty")
	}

	// Option 43 must carry PXE_DISCOVERY_CONTROL with the use-bootfile bit so
	// the UEFI firmware TFTPs the offered NBP instead of doing (unanswered)
	// Boot Server discovery and timing out (PXE-E18).
	opt43 := reply.Options.Get(dhcpv4.OptionVendorSpecificInformation)
	if len(opt43) < 3 {
		t.Fatalf("option 43 missing or too short: %v", opt43)
	}
	if opt43[0] != pxeDiscoveryControlSubOption || opt43[2] != pxeDiscoveryUseBootfile {
		t.Errorf("option 43 = %v, want PXE_DISCOVERY_CONTROL(0x06) len 1 value 0x08", opt43)
	}

	// An already-running iPXE client is chained to the HTTP script and does
	// not need the vendor-class echo.
	ipxeReply, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	srv.addPXEOptions(ipxeReply, archUEFIx64, true)
	if ipxeReply.BootFileName != "http://198.18.1.91:8080/boot.ipxe" {
		t.Errorf("iPXE client boot filename = %q, want the HTTP script", ipxeReply.BootFileName)
	}
}
