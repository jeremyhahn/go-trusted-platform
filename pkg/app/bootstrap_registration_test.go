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
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// The tests below that set the package seams are not parallel; each restores
// the seams it set with t.Cleanup.

const (
	// outboundIP is the address the fake UDP dial reports as the host's
	// outbound address.
	outboundIP = "192.0.2.10"
	// primaryMAC is the hardware address of the interface holding outboundIP.
	primaryMAC = "52:54:00:12:34:56"
)

var (
	errNetworkUnreachable = &net.OpError{Op: "dial", Net: "udp", Err: syscall.ENETUNREACH}
	errInterfaceGone      = &net.OpError{Op: "route", Net: "ip+net", Err: syscall.ENODEV}
)

// fakeUDPConn is the logical UDP connection preferredOutboundIP reads its
// local address from.
type fakeUDPConn struct {
	net.Conn
	local  net.Addr
	dialed string
	closed bool
}

func (c *fakeUDPConn) LocalAddr() net.Addr { return c.local }

func (c *fakeUDPConn) Close() error {
	c.closed = true
	return nil
}

// fakeInterface is one host interface primaryInterfaceInfo walks.
type fakeInterface struct {
	net.Interface
	addrs []net.Addr
	err   error
}

// registrationRequest is one request the fake bootstrap server received.
type registrationRequest struct {
	method      string
	path        string
	contentType string
	reg         BootstrapRegistration
}

func useCmdline(t *testing.T, cmdline string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(path, []byte(cmdline), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	useCmdlinePath(t, path)
}

func useCmdlinePath(t *testing.T, path string) {
	t.Helper()
	saved := procCmdlinePath
	procCmdlinePath = path
	t.Cleanup(func() { procCmdlinePath = saved })
}

func useDial(t *testing.T, dial func(network, address string) (net.Conn, error)) {
	t.Helper()
	saved := dialUDP
	dialUDP = dial
	t.Cleanup(func() { dialUDP = saved })
}

// useOutboundIP makes preferredOutboundIP see ip as the host's outbound
// address and returns the connection the dial hands out.
func useOutboundIP(t *testing.T, ip string) *fakeUDPConn {
	t.Helper()
	conn := &fakeUDPConn{local: &net.UDPAddr{IP: net.ParseIP(ip), Port: 54321}}
	useDial(t, func(network, address string) (net.Conn, error) {
		conn.dialed = network + " " + address
		return conn, nil
	})
	return conn
}

// useNoRoute makes the outbound UDP dial fail as it does on a host with no
// IPv4 route.
func useNoRoute(t *testing.T) {
	t.Helper()
	useDial(t, func(string, string) (net.Conn, error) { return nil, errNetworkUnreachable })
}

func useInterfaceSeams(t *testing.T) {
	t.Helper()
	savedList, savedAddrs := listInterfaces, interfaceAddrs
	t.Cleanup(func() { listInterfaces, interfaceAddrs = savedList, savedAddrs })
}

// useInterfaces makes primaryInterfaceInfo walk ifaces in order.
func useInterfaces(t *testing.T, ifaces ...fakeInterface) {
	t.Helper()
	useInterfaceSeams(t)
	byName := make(map[string]fakeInterface, len(ifaces))
	list := make([]net.Interface, 0, len(ifaces))
	for _, f := range ifaces {
		byName[f.Name] = f
		list = append(list, f.Interface)
	}
	listInterfaces = func() ([]net.Interface, error) { return list, nil }
	interfaceAddrs = func(iface *net.Interface) ([]net.Addr, error) {
		f := byName[iface.Name]
		return f.addrs, f.err
	}
}

func newInterface(t *testing.T, name string, flags net.Flags, mac string, addrs ...net.Addr) fakeInterface {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("parse MAC %q: %v", mac, err)
	}
	return fakeInterface{
		Interface: net.Interface{Name: name, Flags: flags, HardwareAddr: hw},
		addrs:     addrs,
	}
}

func hostAddr(ip string) *net.IPNet {
	return &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(24, 32)}
}

// usePrimaryInterface makes the host look like a machine whose eth0 holds
// outboundIP with primaryMAC.
func usePrimaryInterface(t *testing.T) {
	t.Helper()
	useOutboundIP(t, outboundIP)
	useInterfaces(t, newInterface(t, "eth0", net.FlagUp, primaryMAC, hostAddr(outboundIP)))
}

// newRegistrationServer starts a bootstrap server that answers every request
// with status and hands it to the returned channel. It returns the server's
// host:port, the form platform_debug_sink carries.
func newRegistrationServer(t *testing.T, status int) (string, <-chan registrationRequest) {
	t.Helper()
	requests := make(chan registrationRequest, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := registrationRequest{
			method:      r.Method,
			path:        r.URL.Path,
			contentType: r.Header.Get("Content-Type"),
		}
		if err := json.NewDecoder(r.Body).Decode(&req.reg); err != nil {
			t.Errorf("decode registration: %v", err)
		}
		requests <- req
		w.WriteHeader(status)
	}))
	t.Cleanup(ts.Close)
	return ts.Listener.Addr().String(), requests
}

func receiveRegistration(t *testing.T, requests <-chan registrationRequest) registrationRequest {
	t.Helper()
	select {
	case req := <-requests:
		return req
	case <-time.After(bootstrapRegistrationTimeout):
		t.Fatal("bootstrap server never received a registration request")
		return registrationRequest{}
	}
}

func newTestApp(hostname string) *App {
	return &App{Hostname: hostname, Logger: logging.DefaultLogger()}
}

func TestBootstrapRegistrationSeamDefaults(t *testing.T) {
	if procCmdlinePath != "/proc/cmdline" {
		t.Errorf("procCmdlinePath = %q, want /proc/cmdline", procCmdlinePath)
	}
	seams := []struct {
		name      string
		got, want any
	}{
		{"dialUDP", dialUDP, net.Dial},
		{"listInterfaces", listInterfaces, net.Interfaces},
		{"interfaceAddrs", interfaceAddrs, (*net.Interface).Addrs},
	}
	for _, s := range seams {
		if reflect.ValueOf(s.got).Pointer() != reflect.ValueOf(s.want).Pointer() {
			t.Errorf("%s does not default to the net package function", s.name)
		}
	}
}

func TestParseDebugSinkFromCmdline(t *testing.T) {
	tests := []struct {
		name     string
		cmdline  string
		wantSink string
		wantOK   bool
	}{
		{"present", "root=/dev/sda1 platform_debug_sink=192.0.2.91:8080 quiet\n", "192.0.2.91:8080", true},
		{"absent", "root=/dev/sda1 quiet\n", "", false},
		{"empty value", "root=/dev/sda1 platform_debug_sink= quiet\n", "", false},
		{"empty value then a value", "platform_debug_sink= platform_debug_sink=192.0.2.91:8080\n", "192.0.2.91:8080", true},
		{"prefix of another parameter", "platform_debug_sinks=192.0.2.91:8080\n", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCmdline(t, tt.cmdline)
			sink, ok := parseDebugSinkFromCmdline()
			if sink != tt.wantSink || ok != tt.wantOK {
				t.Errorf("parseDebugSinkFromCmdline() = (%q, %v), want (%q, %v)", sink, ok, tt.wantSink, tt.wantOK)
			}
		})
	}
}

func TestParseDebugSinkFromCmdline_Unreadable(t *testing.T) {
	useCmdlinePath(t, filepath.Join(t.TempDir(), "missing"))
	if sink, ok := parseDebugSinkFromCmdline(); sink != "" || ok {
		t.Errorf("parseDebugSinkFromCmdline() = (%q, %v), want (\"\", false)", sink, ok)
	}
}

func TestRunBootstrapRegistration_PostsToSink(t *testing.T) {
	sink, requests := newRegistrationServer(t, http.StatusOK)
	useCmdline(t, "root=/dev/sda1 platform_debug_sink="+sink+"\n")
	// The dial is the background registration's only seam read; the channel
	// orders it before the seam is restored.
	dialed := make(chan struct{}, 1)
	useDial(t, func(string, string) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, errNetworkUnreachable
	})

	newTestApp("node-01").RunBootstrapRegistration()

	req := receiveRegistration(t, requests)
	// The request follows the dial, so the dial has signalled by now.
	<-dialed
	if req.path != "/installs/node-01/registration.json" {
		t.Errorf("registration path = %q, want /installs/node-01/registration.json", req.path)
	}
	if req.reg.Hostname != "node-01" {
		t.Errorf("registration hostname = %q, want node-01", req.reg.Hostname)
	}
}

func TestRunBootstrapRegistration_NoSink(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
	}{
		{"absent", "root=/dev/sda1 quiet\n"},
		{"empty value", "root=/dev/sda1 platform_debug_sink= quiet\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCmdline(t, tt.cmdline)
			var dialed atomic.Bool
			useDial(t, func(string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, errNetworkUnreachable
			})

			newTestApp("node-01").RunBootstrapRegistration()

			if dialed.Load() {
				t.Error("RunBootstrapRegistration started a registration without a sink")
			}
		})
	}
}

func TestPreferredOutboundIP(t *testing.T) {
	conn := useOutboundIP(t, outboundIP)

	if got := preferredOutboundIP(); got != outboundIP {
		t.Errorf("preferredOutboundIP() = %q, want %q", got, outboundIP)
	}
	if conn.dialed != "udp 1.2.3.4:80" {
		t.Errorf("dialed %q, want \"udp 1.2.3.4:80\"", conn.dialed)
	}
	if !conn.closed {
		t.Error("preferredOutboundIP left the UDP connection open")
	}
}

func TestPreferredOutboundIP_Errors(t *testing.T) {
	t.Run("no route", func(t *testing.T) {
		useNoRoute(t)
		if got := preferredOutboundIP(); got != "" {
			t.Errorf("preferredOutboundIP() = %q, want empty", got)
		}
	})

	t.Run("local address is not UDP", func(t *testing.T) {
		conn := &fakeUDPConn{local: &net.TCPAddr{IP: net.ParseIP(outboundIP), Port: 54321}}
		useDial(t, func(string, string) (net.Conn, error) { return conn, nil })
		if got := preferredOutboundIP(); got != "" {
			t.Errorf("preferredOutboundIP() = %q, want empty", got)
		}
		if !conn.closed {
			t.Error("preferredOutboundIP left the UDP connection open")
		}
	})
}

func TestPrimaryInterfaceInfo(t *testing.T) {
	// Every interface below holds outboundIP but must be passed over: its
	// MAC is never the answer.
	skipped := func(t *testing.T) []fakeInterface {
		broken := newInterface(t, "eth2", net.FlagUp, "02:00:00:00:00:03")
		broken.err = errInterfaceGone
		return []fakeInterface{
			newInterface(t, "lo", net.FlagUp|net.FlagLoopback, "02:00:00:00:00:01", hostAddr(outboundIP)),
			newInterface(t, "eth1", 0, "02:00:00:00:00:02", hostAddr(outboundIP)),
			broken,
			newInterface(t, "eth3", net.FlagUp, "02:00:00:00:00:04",
				&net.IPAddr{IP: net.ParseIP(outboundIP)},
				hostAddr("192.0.2.99"),
				&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)}),
		}
	}

	tests := []struct {
		name    string
		setup   func(t *testing.T)
		wantIP  string
		wantMAC string
	}{
		{
			name: "up non-loopback interface holds the outbound address",
			setup: func(t *testing.T) {
				useOutboundIP(t, outboundIP)
				ifaces := append(skipped(t), newInterface(t, "eth0", net.FlagUp, primaryMAC, hostAddr(outboundIP)))
				useInterfaces(t, ifaces...)
			},
			wantIP:  outboundIP,
			wantMAC: primaryMAC,
		},
		{
			name: "no usable interface holds the outbound address",
			setup: func(t *testing.T) {
				useOutboundIP(t, outboundIP)
				useInterfaces(t, skipped(t)...)
			},
			wantIP: outboundIP,
		},
		{
			name: "interfaces cannot be listed",
			setup: func(t *testing.T) {
				useOutboundIP(t, outboundIP)
				useInterfaceSeams(t)
				listInterfaces = func() ([]net.Interface, error) { return nil, errInterfaceGone }
			},
			wantIP: outboundIP,
		},
		{
			name: "no outbound address",
			setup: func(t *testing.T) {
				useNoRoute(t)
				useInterfaceSeams(t)
				listInterfaces = func() ([]net.Interface, error) {
					t.Error("interfaces listed without an outbound address")
					return nil, errInterfaceGone
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			ip, mac := primaryInterfaceInfo()
			if ip != tt.wantIP || mac != tt.wantMAC {
				t.Errorf("primaryInterfaceInfo() = (%q, %q), want (%q, %q)", ip, mac, tt.wantIP, tt.wantMAC)
			}
		})
	}
}

func TestPostBootstrapRegistration_Success(t *testing.T) {
	usePrimaryInterface(t)
	sink, requests := newRegistrationServer(t, http.StatusOK)

	newTestApp("test-node-01").postBootstrapRegistration(sink)

	// The MAC-keyed path goes first; the hostname-keyed path is the fallback.
	wantPaths := []string{
		"/installs/mac/52-54-00-12-34-56/registration.json",
		"/installs/test-node-01/registration.json",
	}
	if len(requests) != len(wantPaths) {
		t.Fatalf("server received %d requests, want %d", len(requests), len(wantPaths))
	}
	for _, wantPath := range wantPaths {
		req := receiveRegistration(t, requests)
		if req.path != wantPath {
			t.Errorf("registration path = %q, want %q", req.path, wantPath)
		}
		if req.method != http.MethodPut {
			t.Errorf("method = %s, want PUT", req.method)
		}
		if req.contentType != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", req.contentType)
		}

		reg := req.reg
		if reg.Hostname != "test-node-01" || reg.IP != outboundIP || reg.MAC != primaryMAC {
			t.Errorf("registration = (%q, %q, %q), want (test-node-01, %q, %q)",
				reg.Hostname, reg.IP, reg.MAC, outboundIP, primaryMAC)
		}
		if reg.Services["platformd"] != "running" || reg.Services["sshd"] != "running" {
			t.Errorf("services = %v, want platformd and sshd running", reg.Services)
		}
		if _, err := time.Parse(time.RFC3339, reg.Timestamp); err != nil {
			t.Errorf("timestamp %q is not RFC3339: %v", reg.Timestamp, err)
		}
	}
}

func TestPostBootstrapRegistration_NoMAC(t *testing.T) {
	useNoRoute(t)
	sink, requests := newRegistrationServer(t, http.StatusOK)

	newTestApp("test-node-02").postBootstrapRegistration(sink)

	if len(requests) != 1 {
		t.Fatalf("server received %d requests, want only the hostname-keyed one", len(requests))
	}
	req := receiveRegistration(t, requests)
	if req.path != "/installs/test-node-02/registration.json" {
		t.Errorf("registration path = %q, want /installs/test-node-02/registration.json", req.path)
	}
	if req.reg.IP != "" || req.reg.MAC != "" {
		t.Errorf("registration IP, MAC = (%q, %q), want both empty", req.reg.IP, req.reg.MAC)
	}
}

func TestPostBootstrapRegistration_ServerError(t *testing.T) {
	usePrimaryInterface(t)
	sink, requests := newRegistrationServer(t, http.StatusInternalServerError)

	newTestApp("test-node-03").postBootstrapRegistration(sink)

	// A rejected MAC-keyed upload does not stop the hostname-keyed one.
	if len(requests) != 2 {
		t.Fatalf("server received %d requests, want both endpoints tried", len(requests))
	}
}

func TestPostBootstrapRegistration_Unreachable(t *testing.T) {
	useNoRoute(t)

	// Port 1 on loopback refuses the connection at once; the failure is
	// logged, never returned or panicked.
	newTestApp("test-node-04").postBootstrapRegistration("127.0.0.1:1")
}

func TestSanitizeMACForRegistrationPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"valid lowercase", "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff"},
		{"valid uppercase", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff"},
		{"mixed case", "aA:bB:cC:dD:eE:fF", "aa-bb-cc-dd-ee-ff"},
		{"no separators", "aabbccddeeff", "aa-bb-cc-dd-ee-ff"},
		{"too short", "aa:bb:cc", ""},
		{"non-hex chars only", "zz:yy:xx:ww:vv:uu", ""},
		// zz is stripped, leaving 10 hex digits.
		{"mixed valid and invalid chars", "aa:bb:cc:dd:ee:zz", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeMACForRegistrationPath(tt.input); got != tt.want {
				t.Errorf("sanitizeMACForRegistrationPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBootstrapRegistrationPayloadFields(t *testing.T) {
	t.Parallel()

	reg := BootstrapRegistration{
		Hostname:  "host-02",
		IP:        "192.0.2.239",
		MAC:       "00:25:90:00:02:aa",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services: map[string]string{
			"platformd": "running",
			"sshd":      "running",
		},
	}

	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]interface{}
	if unmarshalErr := json.Unmarshal(data, &decoded); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}

	requiredKeys := []string{"hostname", "ip", "mac", "timestamp", "services"}
	for _, key := range requiredKeys {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing required JSON key: %s", key)
		}
	}
}

func TestErrBootstrapRegistration(t *testing.T) {
	t.Parallel()

	cause := &ErrBootstrapRegistrationStatus{
		Endpoint:   "http://192.0.2.91:8080/installs/host-02/registration.json",
		StatusCode: 500,
	}

	err := ErrBootstrapRegistration{
		Endpoint: "http://192.0.2.91:8080/installs/host-02/registration.json",
		Cause:    cause,
	}

	if !strings.Contains(err.Error(), "bootstrap registration") {
		t.Errorf("error message missing 'bootstrap registration': %s", err.Error())
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap did not return the cause")
	}
}

func TestErrBootstrapRegistrationStatus(t *testing.T) {
	t.Parallel()

	err := ErrBootstrapRegistrationStatus{
		Endpoint:   "http://192.0.2.91:8080/installs/host-02/registration.json",
		StatusCode: 404,
	}

	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error message missing status code: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "bootstrap registration") {
		t.Errorf("error message missing 'bootstrap registration': %s", err.Error())
	}
}
