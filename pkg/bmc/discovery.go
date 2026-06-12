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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// redfishEthernetInterface represents a Redfish EthernetInterface resource
// containing the system's MAC address.
type redfishEthernetInterface struct {
	MACAddress string `json:"MACAddress"`
	Name       string `json:"Name"`
}

// macRegexp validates MAC address format (colon-separated hex pairs).
var macRegexp = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

// invalidMACSentinels lists MAC values that are syntactically valid but
// semantically meaningless (broadcast / unset). Some BMCs report these for
// disabled or unpopulated NIC slots; we filter them out so they never reach
// the orchestrator's PXE manifest.
var invalidMACSentinels = map[string]struct{}{
	"ff:ff:ff:ff:ff:ff": {},
	"00:00:00:00:00:00": {},
}

// isValidMAC reports whether the given MAC string passes both the regex
// format check and the sentinel filter.
func isValidMAC(mac string) bool {
	if !macRegexp.MatchString(mac) {
		return false
	}
	_, sentinel := invalidMACSentinels[strings.ToLower(mac)]
	return !sentinel
}

// DiscoverMAC queries the BMC for the system's primary MAC address. It is a
// thin wrapper around DiscoverMACs that returns the first valid MAC found,
// preserved for callers that only need a single identity.
func DiscoverMAC(ctx context.Context, config *Config, logger *slog.Logger) (string, error) {
	macs, err := DiscoverMACs(ctx, config, logger)
	if err != nil {
		return "", err
	}
	return macs[0], nil
}

// DiscoverMACs queries the BMC for ALL of the system's NIC MAC addresses.
//
// MAC discovery is only practical via Redfish: it fetches the
// EthernetInterfaces collection from the first discovered system and returns
// every valid MACAddress found.  IPMI 2.0 over RMCP+ has no standardized way
// to enumerate the host system's NIC MAC addresses (only the BMC's own NIC),
// so when the configured management protocol is IPMI we still attempt a
// Redfish probe and fall through to it if reachable. This matches real-world
// hardware where the same BMC speaks both protocols and users may pick IPMI
// for power/boot operations while Redfish remains available for inventory.
//
// Only when neither Redfish discovery nor a Redfish probe succeeds do we
// surface ErrMACDiscoveryUnsupported, signalling the caller must provide
// MACs manually in the bootstrap config.
func DiscoverMACs(ctx context.Context, config *Config, logger *slog.Logger) ([]string, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}

	protocol := config.Protocol
	if protocol == "" {
		protocol = ProtocolRedfish
	}

	switch protocol {
	case ProtocolRedfish:
		return discoverMACsRedfish(ctx, config, logger)
	case ProtocolIPMI:
		probeTimeout := 5 * time.Second
		if probeRedfish(ctx, config.Address, probeTimeout) {
			logger.Debug("bmc: configured protocol is IPMI but Redfish is reachable; falling through for MAC discovery",
				slog.String("address", config.Address))
			redfishConfig := *config
			redfishConfig.Protocol = ProtocolRedfish
			// IPMI uses UDP/623 but Redfish needs HTTPS — usually on the
			// same port the probe just succeeded against. Override to the
			// Redfish probe port so the EthernetInterfaces walk talks to
			// the HTTPS service rather than the IPMI UDP port the operator
			// originally configured.
			redfishConfig.Port = redfishProbePort
			macs, err := discoverMACsRedfish(ctx, &redfishConfig, logger)
			if err == nil {
				return macs, nil
			}
			logger.Debug("bmc: Redfish fallthrough MAC discovery failed",
				slog.String("address", config.Address),
				slog.String("error", err.Error()))
		}
		return nil, ErrMACDiscoveryUnsupported{Protocol: ProtocolIPMI}
	default:
		return nil, ErrInvalidConfig{Field: "protocol", Reason: "unsupported protocol: " + string(protocol)}
	}
}

// discoverMACsRedfish queries the Redfish EthernetInterfaces endpoint and
// returns every valid MAC address advertised by the system.
func discoverMACsRedfish(ctx context.Context, config *Config, logger *slog.Logger) ([]string, error) {
	rc, err := newRedfishClient(config, logger)
	if err != nil {
		return nil, ErrMACNotFound{Address: config.Address}
	}
	defer rc.Close()

	if err := rc.ensureDiscovered(ctx); err != nil {
		return nil, ErrMACNotFound{Address: config.Address}
	}

	systemPath := rc.getSystemPath()
	if systemPath == "" {
		return nil, ErrMACNotFound{Address: config.Address}
	}

	ethPath := systemPath + "/EthernetInterfaces"

	var collection redfishCollection
	if err := rc.doGET(ctx, ethPath, &collection); err != nil {
		logger.Debug("bmc: failed to fetch EthernetInterfaces",
			slog.String("address", config.Address),
			slog.String("error", err.Error()))
		return nil, ErrMACNotFound{Address: config.Address}
	}

	if len(collection.Members) == 0 {
		return nil, ErrMACNotFound{Address: config.Address}
	}

	macs := make([]string, 0, len(collection.Members))
	seen := make(map[string]struct{}, len(collection.Members))
	for i := range collection.Members {
		memberPath := collection.Members[i].ODataID
		var iface redfishEthernetInterface
		if err := rc.doGET(ctx, memberPath, &iface); err != nil {
			logger.Debug("bmc: failed to fetch EthernetInterface member",
				slog.String("path", memberPath),
				slog.String("error", err.Error()))
			continue
		}
		if !isValidMAC(iface.MACAddress) {
			continue
		}
		key := strings.ToLower(iface.MACAddress)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		macs = append(macs, iface.MACAddress)
	}

	if len(macs) == 0 {
		return nil, ErrMACNotFound{Address: config.Address}
	}

	return macs, nil
}

// DetectProtocol probes the BMC to determine the best available protocol.
// It tries Redfish (HTTPS on port 443) first, then falls back to IPMI (UDP 623).
// If neither protocol responds within the timeout, it returns an empty string.
func DetectProtocol(ctx context.Context, address string, timeout time.Duration) Protocol {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Try Redfish (HTTPS) first.
	if probeRedfish(ctx, address, timeout) {
		return ProtocolRedfish
	}

	// Fall back to IPMI (UDP 623).
	if probeIPMI(ctx, address, timeout) {
		return ProtocolIPMI
	}

	return ""
}

// redfishProbePort is the TCP port DiscoverMAC and DetectProtocol probe for
// Redfish reachability. Defaults to the IANA-assigned 443. Exposed as a
// package-level variable so tests can redirect probes at an httptest server
// running on an ephemeral port without rewriting the production probe path.
var redfishProbePort = 443

// probeRedfish attempts an HTTPS connection to the Redfish service root on
// redfishProbePort. The dial performs standard certificate verification —
// no InsecureSkipVerify. Two outcomes report "Redfish present":
//
//  1. The request completes with a 2xx-4xx status (verifiable cert chain).
//  2. The handshake fails certificate verification. Reaching certificate
//     validation proves a live TLS stack answered on the Redfish port;
//     BMCs ship self-signed certificates by default, so a verification
//     failure is the expected signature of an unprovisioned BMC. No
//     request body is sent on this path — the handshake is abandoned.
//
// Connection failures, timeouts, and 5xx responses report unreachable.
func probeRedfish(ctx context.Context, address string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	defer client.CloseIdleConnections()

	url := fmt.Sprintf("https://%s:%d/redfish/v1/", address, redfishProbePort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return isCertVerificationError(err)
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// isCertVerificationError reports whether err is a TLS certificate
// verification failure. A verification failure proves a live TLS endpoint
// completed a handshake up to certificate validation, which is the probe's
// detection signal for BMCs serving self-signed certificates.
func isCertVerificationError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &invalidErr)
}

// probeIPMI attempts a UDP connection to the standard IPMI/RMCP port.
func probeIPMI(_ context.Context, address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(address, "623"), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send an RMCP presence ping (ASF Presence Pong request).
	// Version 0x06, reserved 0x00, sequence 0xFF, class 0x06 (ASF), ...
	asfPing := []byte{
		0x06, 0x00, 0xFF, 0x06, // RMCP header
		0x00, 0x00, 0x11, 0xBE, // IANA Enterprise Number (ASF)
		0x80, // Message type: Presence Ping
		0x00, // Message tag
		0x00, // Reserved
		0x00, // Data length
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	if _, err := conn.Write(asfPing); err != nil {
		return false
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	// Any response indicates an IPMI-capable BMC.
	return n > 0
}
