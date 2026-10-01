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
		ServerIP:           net.ParseIP("10.4.2.91"),
		RangeStart:         net.ParseIP("10.4.2.220"),
		RangeEnd:           net.ParseIP("10.4.2.230"),
		TFTPServerIP:       net.ParseIP("10.4.2.91"),
		BootFilenameByArch: DefaultBootFilenameByArch(),
		IPXEScript:         "http://10.4.2.91:8080/boot.ipxe",
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
	discover, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	srv.addPXEOptions(reply, discover, archUEFIx64, false)

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
	srv.addPXEOptions(ipxeReply, discover, archUEFIx64, true)
	if ipxeReply.BootFileName != "http://10.4.2.91:8080/boot.ipxe" {
		t.Errorf("iPXE client boot filename = %q, want the HTTP script", ipxeReply.BootFileName)
	}
}

// TestAddPXEOptions_UEFIClientGetsGUIDEchoAndBootOptions is the regression
// guard for #649. A Supermicro X10 UEFI PXE client (Intel UNDI 3.16) sent
// four DISCOVERs and never a REQUEST against an Offer that carried the NBP
// only in the BOOTP header and did not echo its GUID; the legacy ROM on the
// same NIC booted fine. PXE 2.1 §2.2.1 requires the server to echo the
// client's option 97, and a client that asks for options 66/67 may ignore
// the header fields when the options are absent. Both must be in the reply.
func TestAddPXEOptions_UEFIClientGetsGUIDEchoAndBootOptions(t *testing.T) {
	const archUEFIx64 = 0x0007

	srv, err := NewDHCPServer(&DHCPConfig{
		ServerIP:           net.ParseIP("10.4.2.91"),
		RangeStart:         net.ParseIP("10.4.2.220"),
		RangeEnd:           net.ParseIP("10.4.2.230"),
		TFTPServerIP:       net.ParseIP("10.4.2.91"),
		BootFilenameByArch: DefaultBootFilenameByArch(),
		IPXEScript:         "http://10.4.2.91:8080/boot.ipxe",
	}, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("NewDHCPServer: %v", err)
	}

	// The GUID the X10 sent, verbatim: type byte 0 + 16 bytes.
	guid := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3c, 0xec, 0xef, 0x71, 0x4b, 0xa6}
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, guid))

	reply, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	srv.addPXEOptions(reply, req, archUEFIx64, false)

	// Option 97 echoed byte-for-byte.
	if got := reply.Options.Get(dhcpv4.OptionClientMachineIdentifier); string(got) != string(guid) {
		t.Errorf("option 97 = %v, want the client's GUID echoed %v", got, guid)
	}
	// The NBP rides in the BOOTP header (file + siaddr), the form PXE 2.1
	// and every reference PXE server use. Options 66/67 are deliberately
	// NOT added: an Intel UEFI stack that received them completed DHCP
	// and then made no TFTP request at all (#649).
	if reply.BootFileName == "" {
		t.Error("expected the NBP in the BOOTP file field")
	}
	if got := reply.Options.Get(dhcpv4.OptionBootfileName); got != nil {
		t.Errorf("option 67 = %q present; the NBP belongs in the header only", got)
	}
	if got := reply.Options.Get(dhcpv4.OptionTFTPServerName); got != nil {
		t.Errorf("option 66 = %q present; the server belongs in siaddr only", got)
	}

	// A client that sent no GUID must not receive a fabricated one.
	bare, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	noGUID, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	srv.addPXEOptions(noGUID, bare, archUEFIx64, false)
	if got := noGUID.Options.Get(dhcpv4.OptionClientMachineIdentifier); got != nil {
		t.Errorf("option 97 = %v for a client that sent none, want absent", got)
	}

	// An iPXE client is chained to the script; the header is the contract
	// there and options 66/67 must not point it back at TFTP.
	ipxeReq, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	ipxeReply, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	srv.addPXEOptions(ipxeReply, ipxeReq, archUEFIx64, true)
	if got := ipxeReply.Options.Get(dhcpv4.OptionTFTPServerName); got != nil {
		t.Errorf("iPXE reply carries option 66 %q; the HTTP chain must not be redirected to TFTP", got)
	}
}
