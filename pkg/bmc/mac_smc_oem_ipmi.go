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

import (
	"context"
	"log/slog"
	"net"
)

// Supermicro OEM IPMI command for "Get LAN1 MAC Address".
//
// WHY THIS EXISTS — the X10 ATEN BMC (firmware 4.0.x) does not populate
// the host system's Redfish EthernetInterfaces collection, and IPMI 2.0
// has no standard command for the HOST's NIC MACs (only the BMC's own
// NIC via Get LAN Configuration). The OEM NetFn 0x30 / Cmd 0x21 command
// is the documented Supermicro path (used by SUM and ipmitool raw
// recipes) that returns the host LAN1 MAC out-of-band, making PXE
// manifest generation possible without booting the node.
//
// Response payload after the completion code (which the RMCP+ transport
// strips and checks): 6 bytes of MAC. Some firmware revisions carry an
// extra reserved/echo byte, yielding 7 data bytes; parseSmcOEMHostMAC
// handles both shapes defensively.
const smcOEMCmdHostMAC = 0x21

// ipmiOEMHostMAC attempts Supermicro OEM host-MAC discovery by opening a
// short-lived IPMI client against config. It is a package-level variable
// so unit tests can swap in an in-memory implementation without touching
// the network — the same test-seam pattern as redfishProbePort in
// discovery.go. Production callers never reassign it.
var ipmiOEMHostMAC = func(ctx context.Context, config *Config, logger *slog.Logger) (string, error) {
	client := newIPMIClient(config, logger)
	defer client.Close()
	return client.HostMACAddress(ctx)
}

// HostMACAddress queries the host system's primary (LAN1) NIC MAC address
// out-of-band via the Supermicro OEM IPMI command NetFn 0x30 / Cmd 0x21,
// reusing the client's already-open RMCP+ session.
//
// The command is gated to Supermicro-family BMCs using the same
// IANA-based vendor detection that routes the OEM boot override
// (manufacturerName → ianaToVendor). The check is deliberately
// model-independent: rebadged boards such as the VeloCloud EDGE840
// (Supermicro X10SDV silicon under an OEM SMBIOS skin with an empty
// model string) still report the Supermicro IANA enterprise number over
// IPMI, so they take the OEM path like any other X10.
//
// Non-Supermicro vendors receive ErrMACDiscoveryUnsupported — the same
// typed error the pre-OEM dispatch surfaced for the IPMI protocol — so
// callers' fallback behavior is unchanged. Malformed responses surface
// ErrOEMMACParse; wire failures surface ErrOEMMACCommand.
func (c *ipmiClient) HostMACAddress(ctx context.Context) (string, error) {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return "", acqErr
	}
	defer release()
	if c.manufacturerName(ctx) != vendorKeySupermicro {
		return "", ErrMACDiscoveryUnsupported{Protocol: ProtocolIPMI}
	}
	return sendSmcOEMHostMAC(c.session, c.logger)
}

// sendSmcOEMHostMAC issues the Supermicro OEM 0x30/0x21 "Get LAN1 MAC
// Address" over an already-open RMCP+ session and parses the response.
// Both *rmcpSession and the in-process test doubles satisfy
// ipmiRawSender, so the wire logic stays in one place — mirroring
// sendSmcOEMBootOverride in vboot_smc_oem_ipmi.go.
func sendSmcOEMHostMAC(sender ipmiRawSender, logger *slog.Logger) (string, error) {
	resp, err := sender.Send(smcOEMNetFn, smcOEMCmdHostMAC, nil)
	if err != nil {
		return "", ErrOEMMACCommand{Cause: err}
	}
	mac, err := parseSmcOEMHostMAC(resp)
	if err != nil {
		return "", err
	}
	logger.Debug("bmc: host MAC discovered via smc-oem-ipmi",
		slog.String("mac", mac))
	return mac, nil
}

// parseSmcOEMHostMAC extracts a plausible unicast MAC address from the
// OEM 0x30/0x21 response data (completion code already stripped by the
// transport). Accepted shapes:
//
//   - 6 bytes: the MAC itself.
//   - 7 bytes: a reserved/echo byte plus the MAC. The trailing 6 bytes
//     are preferred; the leading 6 are tried as a fallback in case the
//     extra byte is appended rather than prepended.
//   - 10 bytes: a 4-byte OEM header (3-byte IANA enterprise number plus
//     a reserved byte) followed by the MAC — the shape the X10 ATEN
//     BMC 4.0 returns on real hardware (verified against a chassis
//     whose MAC was independently known). The trailing 6 bytes are
//     preferred; the leading 6 are the defensive fallback.
//
// Any other length, or a candidate that is not a plausible unicast MAC
// (multicast bit set, all-zero, broadcast), returns ErrOEMMACParse
// carrying the raw byte count.
func parseSmcOEMHostMAC(data []byte) (string, error) {
	var candidates [][]byte
	switch len(data) {
	case 6:
		candidates = [][]byte{data}
	case 7:
		candidates = [][]byte{data[1:7], data[0:6]}
	case 10:
		candidates = [][]byte{data[4:10], data[0:6]}
	default:
		return "", ErrOEMMACParse{Bytes: len(data)}
	}
	for _, candidate := range candidates {
		if mac, ok := plausibleUnicastMAC(candidate); ok {
			return mac, nil
		}
	}
	return "", ErrOEMMACParse{Bytes: len(data)}
}

// plausibleUnicastMAC formats b as a colon-separated MAC string and
// reports whether it is a plausible unicast hardware address: exactly 6
// bytes, multicast/broadcast bit clear, and not one of the semantically
// meaningless sentinels (all-zero) filtered by isValidMAC.
func plausibleUnicastMAC(b []byte) (string, bool) {
	if len(b) != 6 {
		return "", false
	}
	if b[0]&0x01 != 0 {
		// Multicast (and therefore also broadcast ff:...) — a host NIC
		// never carries a multicast address as its burned-in MAC.
		return "", false
	}
	mac := net.HardwareAddr(b).String()
	if !isValidMAC(mac) {
		return "", false
	}
	return mac, true
}
