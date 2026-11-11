package system

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// errHostSeam is the typed error the fake host seams return.
type errHostSeam struct{ op string }

func (e *errHostSeam) Error() string { return "host seam: " + e.op + " failed" }

// The tests in this file swap package-level host seams, so none of them
// calls t.Parallel.

func setOpenCPUInfo(t *testing.T, open func() (io.ReadCloser, error)) {
	t.Helper()
	orig := openCPUInfo
	openCPUInfo = open
	t.Cleanup(func() { openCPUInfo = orig })
}

func setGeteuid(t *testing.T, uid int) {
	t.Helper()
	orig := geteuid
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = orig })
}

// setDMIFiles makes readHostFile serve the DMI attribute's own file name
// (e.g. "bios_vendor") as its contents, padded with whitespace that
// readDMIFile must trim.
func setDMIFiles(t *testing.T) {
	t.Helper()
	orig := readHostFile
	readHostFile = func(path string) ([]byte, error) {
		return []byte("  " + filepath.Base(path) + "\n"), nil
	}
	t.Cleanup(func() { readHostFile = orig })
}

func setNetwork(t *testing.T, ifaces []net.Interface, ifaceErr error, addrs map[string][]net.Addr, addrErrs map[string]error) {
	t.Helper()
	origIfaces, origAddrs := netInterfaces, interfaceAddrs
	netInterfaces = func() ([]net.Interface, error) { return ifaces, ifaceErr }
	interfaceAddrs = func(iface net.Interface) ([]net.Addr, error) {
		return addrs[iface.Name], addrErrs[iface.Name]
	}
	t.Cleanup(func() { netInterfaces, interfaceAddrs = origIfaces, origAddrs })
}

const fakeCPUInfo = `processor	: 0
model name	: Fake CPU @ 3.00GHz
cpu cores	: 2
cache size	: 512 KB
flags		: fpu sse avx

processor	: 1
model name	: Second Model Ignored
cpu cores	: 8
cache size	: 1 KB
flags		: ignored
no colon line
`

func TestCPUInfoSeam(t *testing.T) {
	setOpenCPUInfo(t, func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(fakeCPUInfo)), nil
	})

	info, err := CPUInfo()
	if err != nil {
		t.Fatalf("CPUInfo: %v", err)
	}
	if info.ModelName != "Fake CPU @ 3.00GHz" {
		t.Errorf("ModelName = %q", info.ModelName)
	}
	if info.Cores != 2 || info.Threads != 2 {
		t.Errorf("Cores/Threads = %d/%d, want 2/2", info.Cores, info.Threads)
	}
	if info.CacheSize != "512 KB" {
		t.Errorf("CacheSize = %q", info.CacheSize)
	}
	if strings.Join(info.Flags, ",") != "fpu,sse,avx" {
		t.Errorf("Flags = %v", info.Flags)
	}
}

func TestCPUInfoSeamErrors(t *testing.T) {
	openErr := &errHostSeam{op: "open"}
	scanErr := &errHostSeam{op: "read"}
	tests := []struct {
		name string
		open func() (io.ReadCloser, error)
		want error
	}{
		{
			name: "open fails",
			open: func() (io.ReadCloser, error) { return nil, openErr },
			want: openErr,
		},
		{
			name: "scan fails",
			open: func() (io.ReadCloser, error) {
				r := io.MultiReader(strings.NewReader("processor\t: 0\n"), iotest.ErrReader(scanErr))
				return io.NopCloser(r), nil
			},
			want: scanErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOpenCPUInfo(t, tt.open)
			_, err := CPUInfo()
			var seamErr *errHostSeam
			if !errors.As(err, &seamErr) || !errors.Is(err, tt.want) {
				t.Fatalf("CPUInfo error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSystemInfoRoot(t *testing.T) {
	setOpenCPUInfo(t, func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(fakeCPUInfo)), nil
	})
	setGeteuid(t, 0)
	setDMIFiles(t)

	sys, err := SystemInfo()
	if err != nil {
		t.Fatalf("SystemInfo: %v", err)
	}
	if sys.CPU == nil || sys.CPU.ModelName != "Fake CPU @ 3.00GHz" {
		t.Fatalf("CPU = %+v", sys.CPU)
	}
	if sys.BIOS == nil || sys.BIOS.Vendor != "bios_vendor" || sys.BIOS.Date != "bios_date" {
		t.Errorf("BIOS = %+v", sys.BIOS)
	}
	if sys.Board == nil || sys.Board.Name != "board_name" || sys.Board.Serial != "board_serial" {
		t.Errorf("Board = %+v", sys.Board)
	}
	if sys.Chassis == nil || sys.Chassis.Type != "chassis_type" || sys.Chassis.AssetTag != "chassis_asset_tag" {
		t.Errorf("Chassis = %+v", sys.Chassis)
	}
	if sys.Product == nil || sys.Product.UUID != "product_uuid" || sys.Product.SKU != "product_sku" {
		t.Errorf("Product = %+v", sys.Product)
	}

	if err := PrintSystemInfo(); err != nil {
		t.Errorf("PrintSystemInfo: %v", err)
	}
}

func TestSystemInfoNonRoot(t *testing.T) {
	setOpenCPUInfo(t, func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(fakeCPUInfo)), nil
	})
	setGeteuid(t, 1000)
	setDMIFiles(t)

	sys, err := SystemInfo()
	if err != nil {
		t.Fatalf("SystemInfo: %v", err)
	}
	if sys.BIOS != nil || sys.Board != nil || sys.Chassis != nil || sys.Product != nil {
		t.Errorf("non-root SystemInfo read DMI: %+v", sys)
	}
	if sys.CPU == nil || sys.CPU.Threads != 2 {
		t.Errorf("CPU = %+v", sys.CPU)
	}
}

func TestSystemInfoCPUError(t *testing.T) {
	openErr := &errHostSeam{op: "open"}
	setOpenCPUInfo(t, func() (io.ReadCloser, error) { return nil, openErr })

	sys, err := SystemInfo()
	if !errors.Is(err, openErr) {
		t.Fatalf("SystemInfo error = %v, want %v", err, openErr)
	}
	if sys.Runtime == nil || sys.CPU != nil {
		t.Errorf("SystemInfo on CPU error = %+v, want runtime only", sys)
	}
	if err := PrintSystemInfo(); !errors.Is(err, openErr) {
		t.Errorf("PrintSystemInfo error = %v, want %v", err, openErr)
	}
}

func TestReadDMIFileSeamError(t *testing.T) {
	orig := readHostFile
	readHostFile = func(string) ([]byte, error) { return nil, &errHostSeam{op: "read"} }
	t.Cleanup(func() { readHostFile = orig })

	if got := readDMIFile("/sys/class/dmi/id/bios_vendor"); got != "" {
		t.Errorf("readDMIFile on error = %q, want empty", got)
	}
}

func TestNetworkInfoDetailsSeam(t *testing.T) {
	up := net.FlagUp
	ifaces := []net.Interface{
		{Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
		{Name: "down0", Flags: 0},
		{Name: "err0", Flags: up},
		{Name: "eth0", Flags: up},
		{Name: "eth1", Flags: up},
	}
	ipNet := func(s string) *net.IPNet { return &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(24, 32)} }
	addrs := map[string][]net.Addr{
		"down0": {ipNet("192.0.2.99")},
		"err0":  {ipNet("192.0.2.98")},
		"eth0": {
			&net.IPAddr{IP: net.ParseIP("192.0.2.97")}, // not an *net.IPNet
			ipNet("127.0.0.2"),
			ipNet("fe80::1"),
			ipNet("192.0.2.10"),
			ipNet("2001:db8::10"),
		},
		"eth1": {
			ipNet("192.0.2.20"),
			ipNet("2001:db8::20"),
		},
	}
	addrErrs := map[string]error{"err0": &errHostSeam{op: "addrs"}}
	setNetwork(t, ifaces, nil, addrs, addrErrs)

	info := NetworkInfoDetails()
	if got := strings.Join(info.Interfaces, ","); got != "err0,eth0,eth1" {
		t.Errorf("Interfaces = %q, want err0,eth0,eth1", got)
	}
	if info.IPv4 != "192.0.2.10" {
		t.Errorf("IPv4 = %q, want 192.0.2.10", info.IPv4)
	}
	if info.IPv6 != "2001:db8::10" {
		t.Errorf("IPv6 = %q, want 2001:db8::10", info.IPv6)
	}
}

func TestNetworkInfoDetailsSeamInterfacesError(t *testing.T) {
	setNetwork(t, nil, &errHostSeam{op: "interfaces"}, nil, nil)

	info := NetworkInfoDetails()
	if info == nil {
		t.Fatal("NetworkInfoDetails returned nil")
	}
	if len(info.Interfaces) != 0 || info.IPv4 != "" || info.IPv6 != "" {
		t.Errorf("NetworkInfoDetails on error = %+v, want no interfaces or addresses", info)
	}
}
