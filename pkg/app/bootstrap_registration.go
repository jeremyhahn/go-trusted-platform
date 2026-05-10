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

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// bootstrapRegistrationTimeout is the maximum time allowed for the
	// registration POST to complete. The registration is best-effort and
	// must never block platformd startup.
	bootstrapRegistrationTimeout = 10 * time.Second

	// kernelCmdlineParam is the kernel command-line parameter that indicates
	// bootstrap mode. Its value is the host:port of the bootstrap server's
	// forensic/sink HTTP endpoint.
	kernelCmdlineParam = "platform_debug_sink"

	// procCmdlinePath is the path to the kernel cmdline pseudo-file.
	// Declared as a variable so tests can override it.
	procCmdlinePath = "/proc/cmdline"
)

// ErrBootstrapRegistration is returned when the bootstrap registration POST fails.
type ErrBootstrapRegistration struct {
	Endpoint string
	Cause    error
}

// Error returns the error message.
func (e ErrBootstrapRegistration) Error() string {
	return fmt.Sprintf("app: bootstrap registration to %s failed: %v", e.Endpoint, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBootstrapRegistration) Unwrap() error { return e.Cause }

// ErrBootstrapRegistrationStatus is returned when the bootstrap server responds
// with a non-2xx status code.
type ErrBootstrapRegistrationStatus struct {
	Endpoint   string
	StatusCode int
}

// Error returns the error message.
func (e ErrBootstrapRegistrationStatus) Error() string {
	return fmt.Sprintf("app: bootstrap registration to %s returned status %d", e.Endpoint, e.StatusCode)
}

// BootstrapRegistration is the JSON payload POSTed to the bootstrap server
// so the orchestrator can discover the node's runtime network identity.
type BootstrapRegistration struct {
	Hostname  string            `json:"hostname"`
	IP        string            `json:"ip"`
	MAC       string            `json:"mac"`
	Timestamp string            `json:"timestamp"`
	Services  map[string]string `json:"services"`
}

// RunBootstrapRegistration checks the kernel cmdline for the platform_debug_sink
// parameter. If present, it fires a non-blocking goroutine that POSTs this node's
// runtime state (hostname, IP, MAC) to the bootstrap server. The goroutine uses
// a 10-second context timeout and logs warnings on failure without blocking the
// caller.
func (app *App) RunBootstrapRegistration() {
	sink, ok := parseDebugSinkFromCmdline()
	if !ok {
		return
	}

	app.Logger.Info("bootstrap registration: detected platform_debug_sink, will register with bootstrap server",
		"sink", sink)

	go app.postBootstrapRegistration(sink)
}

// postBootstrapRegistration performs the actual HTTP POST. It runs in its own
// goroutine and is expected to complete within bootstrapRegistrationTimeout.
func (app *App) postBootstrapRegistration(sink string) {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapRegistrationTimeout)
	defer cancel()

	hostname := app.Hostname
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			app.Logger.Warn("bootstrap registration: failed to get hostname", "error", err)
			return
		}
		hostname = h
	}

	ip, mac := primaryInterfaceInfo()

	reg := BootstrapRegistration{
		Hostname:  hostname,
		IP:        ip,
		MAC:       mac,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services: map[string]string{
			"platformd": "running",
			"sshd":      "running",
		},
	}

	body, err := json.Marshal(reg)
	if err != nil {
		app.Logger.Warn("bootstrap registration: failed to marshal payload", "error", err)
		return
	}

	// Publish to the MAC-keyed path (primary) and the hostname-keyed
	// path (fallback). The orchestrator's fetchRegistrationIP tries the
	// MAC path first because a shared ISO bakes a generic hostname like
	// "server" that doesn't correlate with the per-node hostname in
	// bootstrap.yaml. MAC is self-determined and matches the identity
	// the orchestrator already knows for this node. Both uploads are
	// best-effort; a failure on either doesn't block the other.
	endpoints := []string{
		fmt.Sprintf("http://%s/installs/%s/registration.json", sink, hostname),
	}
	if macPath := sanitizeMACForRegistrationPath(mac); macPath != "" {
		endpoints = append([]string{
			fmt.Sprintf("http://%s/installs/mac/%s/registration.json", sink, macPath),
		}, endpoints...)
	}

	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
		if err != nil {
			app.Logger.Warn("bootstrap registration: failed to create request",
				"endpoint", endpoint, "error", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			app.Logger.Warn("bootstrap registration: request failed",
				"endpoint", endpoint, "error", err)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			app.Logger.Warn("bootstrap registration: non-success response",
				"endpoint", endpoint, "status", resp.StatusCode)
			continue
		}

		app.Logger.Info("bootstrap registration: successfully registered with bootstrap server",
			"endpoint", endpoint,
			"hostname", hostname,
			"ip", ip,
			"mac", mac,
		)
	}
}

// sanitizeMACForRegistrationPath normalizes a MAC to the URL-safe
// dash-separated form used by the pxeboot server. "aa:BB:cc:DD:ee:ff"
// → "aa-bb-cc-dd-ee-ff". Returns empty string when the input doesn't
// contain exactly 12 hex digits so the caller can skip the MAC path
// and fall back to the hostname path.
func sanitizeMACForRegistrationPath(mac string) string {
	var hex []byte
	for i := 0; i < len(mac); i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9':
			hex = append(hex, c)
		case c >= 'a' && c <= 'f':
			hex = append(hex, c)
		case c >= 'A' && c <= 'F':
			hex = append(hex, c+('a'-'A'))
		}
	}
	if len(hex) != 12 {
		return ""
	}
	out := make([]byte, 0, 17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			out = append(out, '-')
		}
		out = append(out, hex[i], hex[i+1])
	}
	return string(out)
}

// parseDebugSinkFromCmdline reads /proc/cmdline and extracts the value of the
// platform_debug_sink=<host:port> parameter. Returns the value and true if
// found, or an empty string and false if absent or unreadable.
func parseDebugSinkFromCmdline() (string, bool) {
	data, err := os.ReadFile(procCmdlinePath)
	if err != nil {
		return "", false
	}
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, kernelCmdlineParam+"=") {
			val := strings.TrimPrefix(field, kernelCmdlineParam+"=")
			if val != "" {
				return val, true
			}
		}
	}
	return "", false
}

// primaryInterfaceInfo discovers the IP address and MAC of the primary network
// interface by finding the interface whose address matches the preferred outbound
// IPv4 address. Returns empty strings if the information cannot be determined.
func primaryInterfaceInfo() (string, string) {
	preferredIP := preferredOutboundIP()
	if preferredIP == "" {
		return "", ""
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return preferredIP, ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() != nil && ipNet.IP.String() == preferredIP {
				return preferredIP, iface.HardwareAddr.String()
			}
		}
	}

	return preferredIP, ""
}

// preferredOutboundIP returns the local IPv4 address the OS would use to reach
// an external destination. Uses a connectionless UDP dial to avoid actual traffic.
func preferredOutboundIP() string {
	conn, err := net.Dial("udp", "1.2.3.4:80")
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return localAddr.IP.String()
}
