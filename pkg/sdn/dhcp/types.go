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

package dhcp

import (
	"context"
	"net"
	"net/netip"
	"time"
)

const (
	// DefaultLeaseDuration is the default DHCP lease duration.
	DefaultLeaseDuration = 24 * time.Hour

	// DefaultRenewalTime is the default T1 renewal time (50% of lease).
	DefaultRenewalTime = 12 * time.Hour

	// DefaultRebindingTime is the default T2 rebinding time (87.5% of lease).
	DefaultRebindingTime = 21 * time.Hour

	// IPAMBackendMemory uses in-memory storage for leases.
	IPAMBackendMemory = "memory"

	// IPAMBackendQuicBaaS uses QuicBaaS for distributed lease storage.
	IPAMBackendQuicBaaS = "quicbaas"

	// IPAMBackendDHT uses a distributed hash table for lease storage.
	IPAMBackendDHT = "dht"

	// NetworkPublic represents a public-facing network.
	NetworkPublic = "public"

	// NetworkPrivate represents a private/internal network.
	NetworkPrivate = "private"
)

// ServerConfig configures the DHCP server.
type ServerConfig struct {
	// Interfaces to bind (supports multiple).
	Interfaces []InterfaceConfig

	// DefaultLeaseDuration is the default lease duration for all interfaces.
	// Individual interfaces can override this.
	DefaultLeaseDuration time.Duration

	// IPAMBackend specifies the IPAM storage backend.
	// Valid values: "memory", "quicbaas", "dht".
	IPAMBackend string

	// IPAMConfig contains backend-specific configuration.
	IPAMConfig map[string]string
}

// Clone returns a deep copy of the ServerConfig.
func (c *ServerConfig) Clone() *ServerConfig {
	if c == nil {
		return nil
	}
	clone := &ServerConfig{
		DefaultLeaseDuration: c.DefaultLeaseDuration,
		IPAMBackend:          c.IPAMBackend,
	}
	if c.Interfaces != nil {
		clone.Interfaces = make([]InterfaceConfig, len(c.Interfaces))
		for i, iface := range c.Interfaces {
			clone.Interfaces[i] = *iface.Clone()
		}
	}
	if c.IPAMConfig != nil {
		clone.IPAMConfig = make(map[string]string, len(c.IPAMConfig))
		for k, v := range c.IPAMConfig {
			clone.IPAMConfig[k] = v
		}
	}
	return clone
}

// Validate checks if the server configuration is valid.
func (c *ServerConfig) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}
	if len(c.Interfaces) == 0 {
		return ErrNoInterfacesConfigured
	}
	for i := range c.Interfaces {
		if err := c.Interfaces[i].Validate(); err != nil {
			return err
		}
	}
	if c.IPAMBackend != "" {
		switch c.IPAMBackend {
		case IPAMBackendMemory, IPAMBackendQuicBaaS, IPAMBackendDHT:
			// Valid backends
		default:
			return ErrIPAMBackendInvalid
		}
	}
	return nil
}

// InterfaceConfig configures a single interface binding.
type InterfaceConfig struct {
	// Name is the interface name (eth0, br0, etc.).
	Name string

	// Network specifies the network type ("public" or "private").
	Network string

	// Address is the server address on this interface.
	Address netip.Addr

	// PoolID is the IPAM pool ID for this interface.
	PoolID string

	// Options contains DHCP options for this network.
	Options DHCPOptions
}

// Clone returns a deep copy of the InterfaceConfig.
func (c *InterfaceConfig) Clone() *InterfaceConfig {
	if c == nil {
		return nil
	}
	clone := &InterfaceConfig{
		Name:    c.Name,
		Network: c.Network,
		Address: c.Address,
		PoolID:  c.PoolID,
		Options: *c.Options.Clone(),
	}
	return clone
}

// Validate checks if the interface configuration is valid.
func (c *InterfaceConfig) Validate() error {
	if c == nil {
		return ErrInvalidInterface
	}
	if c.Name == "" {
		return ErrInvalidInterface
	}
	if !c.Address.IsValid() {
		return ErrInvalidInterface
	}
	if c.PoolID == "" {
		return ErrPoolIDRequired
	}
	if c.Network != "" && c.Network != NetworkPublic && c.Network != NetworkPrivate {
		return ErrInvalidInterface
	}
	return nil
}

// DHCPOptions holds common DHCP response options.
type DHCPOptions struct {
	// SubnetMask is the subnet mask for the network.
	SubnetMask net.IPMask

	// Router is the default gateway IP address.
	Router netip.Addr

	// DNS is the list of DNS server addresses.
	DNS []netip.Addr

	// DomainName is the domain name for the network.
	DomainName string

	// LeaseTime is the default lease duration.
	LeaseTime time.Duration

	// RenewalTime (T1) is when the client should start unicast renewal.
	RenewalTime time.Duration

	// RebindTime (T2) is when the client should start broadcast renewal.
	RebindTime time.Duration

	// NTPServers is the list of NTP server addresses.
	NTPServers []netip.Addr

	// MTU is the maximum transmission unit for the interface.
	MTU uint16

	// Hostname is the hostname to assign to the client.
	Hostname string

	// NextServer is the TFTP server for PXE boot.
	NextServer net.IP

	// BootFileName is the PXE boot file name.
	BootFileName string
}

// Clone returns a deep copy of DHCPOptions.
func (o *DHCPOptions) Clone() *DHCPOptions {
	if o == nil {
		return nil
	}
	clone := *o
	if o.SubnetMask != nil {
		clone.SubnetMask = make(net.IPMask, len(o.SubnetMask))
		copy(clone.SubnetMask, o.SubnetMask)
	}
	if o.DNS != nil {
		clone.DNS = make([]netip.Addr, len(o.DNS))
		copy(clone.DNS, o.DNS)
	}
	if o.NTPServers != nil {
		clone.NTPServers = make([]netip.Addr, len(o.NTPServers))
		copy(clone.NTPServers, o.NTPServers)
	}
	if o.NextServer != nil {
		clone.NextServer = make(net.IP, len(o.NextServer))
		copy(clone.NextServer, o.NextServer)
	}
	return &clone
}

// Validate checks if the DHCP options are valid.
func (o *DHCPOptions) Validate() error {
	if o.LeaseTime == 0 {
		o.LeaseTime = DefaultLeaseDuration
	}
	if o.RenewalTime == 0 {
		o.RenewalTime = o.LeaseTime / 2 // Default T1 = 50% of lease
	}
	if o.RebindTime == 0 {
		o.RebindTime = o.LeaseTime * 7 / 8 // Default T2 = 87.5% of lease
	}
	return nil
}

// Lease represents a DHCP lease record.
type Lease struct {
	// IP is the leased IP address.
	IP netip.Addr

	// MAC is the client's MAC address.
	MAC net.HardwareAddr

	// Hostname is the client's hostname.
	Hostname string

	// PoolID is the IPAM pool ID.
	PoolID string

	// Interface is the interface this lease was served on.
	Interface string

	// ClientID is the DHCP client identifier.
	ClientID []byte

	// VendorClass is the vendor class identifier (option 60).
	VendorClass string

	// UserClass is the user class information (option 77).
	UserClass string

	// LeasedAt is when the lease was created.
	LeasedAt time.Time

	// ExpiresAt is when the lease expires.
	ExpiresAt time.Time

	// RenewedAt is when the lease was last renewed.
	RenewedAt time.Time

	// State is the current state of the lease.
	State LeaseState
}

// Clone returns a deep copy of the Lease.
func (l *Lease) Clone() *Lease {
	if l == nil {
		return nil
	}
	clone := *l
	if l.MAC != nil {
		clone.MAC = make(net.HardwareAddr, len(l.MAC))
		copy(clone.MAC, l.MAC)
	}
	if l.ClientID != nil {
		clone.ClientID = make([]byte, len(l.ClientID))
		copy(clone.ClientID, l.ClientID)
	}
	return &clone
}

// IsExpired returns true if the lease has expired.
func (l *Lease) IsExpired() bool {
	if l.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(l.ExpiresAt)
}

// IsActive returns true if the lease is currently active.
func (l *Lease) IsActive() bool {
	return l.State == LeaseStateActive && !l.IsExpired()
}

// TimeRemaining returns the time remaining on the lease.
func (l *Lease) TimeRemaining() time.Duration {
	if l.ExpiresAt.IsZero() {
		return 0
	}
	remaining := time.Until(l.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// LeaseState tracks lease status.
type LeaseState int

const (
	// LeaseStateActive indicates the lease is currently in use.
	LeaseStateActive LeaseState = iota

	// LeaseStateExpired indicates the lease has expired.
	LeaseStateExpired

	// LeaseStateReleased indicates the lease was explicitly released.
	LeaseStateReleased

	// LeaseStateDeclined indicates the client declined the offered address.
	LeaseStateDeclined
)

// String returns the string representation of LeaseState.
func (s LeaseState) String() string {
	switch s {
	case LeaseStateActive:
		return "active"
	case LeaseStateExpired:
		return "expired"
	case LeaseStateReleased:
		return "released"
	case LeaseStateDeclined:
		return "declined"
	default:
		return "unknown"
	}
}

// IsValid returns true if the state is a recognized value.
func (s LeaseState) IsValid() bool {
	switch s {
	case LeaseStateActive, LeaseStateExpired, LeaseStateReleased, LeaseStateDeclined:
		return true
	default:
		return false
	}
}

// ServerStats contains server statistics.
type ServerStats struct {
	// StartedAt is when the server was started.
	StartedAt time.Time

	// PacketsReceived is the total number of DHCP packets received.
	PacketsReceived uint64

	// PacketsSent is the total number of DHCP packets sent.
	PacketsSent uint64

	// DiscoverCount is the number of DHCPDISCOVER messages received.
	DiscoverCount uint64

	// OfferCount is the number of DHCPOFFER messages sent.
	OfferCount uint64

	// RequestCount is the number of DHCPREQUEST messages received.
	RequestCount uint64

	// AckCount is the number of DHCPACK messages sent.
	AckCount uint64

	// NakCount is the number of DHCPNAK messages sent.
	NakCount uint64

	// ReleaseCount is the number of DHCPRELEASE messages received.
	ReleaseCount uint64

	// DeclineCount is the number of DHCPDECLINE messages received.
	DeclineCount uint64

	// InformCount is the number of DHCPINFORM messages received.
	InformCount uint64

	// ErrorCount is the total number of errors encountered.
	ErrorCount uint64

	// ActiveLeases is the current number of active leases.
	ActiveLeases int
}

// Clone returns a deep copy of the ServerStats.
func (s *ServerStats) Clone() *ServerStats {
	if s == nil {
		return nil
	}
	clone := *s
	return &clone
}

// PXEOptions holds PXE boot configuration.
type PXEOptions struct {
	// NextServer is the TFTP server IP address.
	NextServer net.IP

	// BootFileName is the path to the boot file on the TFTP server.
	BootFileName string

	// TFTPRoot is the root directory for TFTP files.
	TFTPRoot string

	// ArchitectureFilters maps client architecture to boot files.
	// Key is the architecture code (e.g., 7 for UEFI x64).
	ArchitectureFilters map[uint16]string
}

// Clone returns a deep copy of PXEOptions.
func (o *PXEOptions) Clone() *PXEOptions {
	if o == nil {
		return nil
	}
	clone := *o
	if o.NextServer != nil {
		clone.NextServer = make(net.IP, len(o.NextServer))
		copy(clone.NextServer, o.NextServer)
	}
	if o.ArchitectureFilters != nil {
		clone.ArchitectureFilters = make(map[uint16]string, len(o.ArchitectureFilters))
		for k, v := range o.ArchitectureFilters {
			clone.ArchitectureFilters[k] = v
		}
	}
	return &clone
}

// Validate checks if the PXE options are valid.
func (o *PXEOptions) Validate() error {
	if o.NextServer == nil || o.NextServer.IsUnspecified() {
		return ErrInvalidNextServer
	}
	if o.BootFileName == "" {
		return ErrInvalidBootFile
	}
	return nil
}

// GetBootFileForArch returns the boot file for the given architecture.
func (o *PXEOptions) GetBootFileForArch(arch uint16) string {
	if o.ArchitectureFilters != nil {
		if bootFile, ok := o.ArchitectureFilters[arch]; ok {
			return bootFile
		}
	}
	return o.BootFileName
}

// LeaseRequest contains parameters for requesting a lease.
type LeaseRequest struct {
	// MAC is the client's hardware address.
	MAC net.HardwareAddr

	// PoolID is the pool to allocate from.
	PoolID string

	// Interface is the interface the request came from.
	Interface string

	// Hostname is the optional client hostname.
	Hostname string

	// RequestedIP is an optional specific IP to request.
	RequestedIP netip.Addr

	// LeaseDuration overrides the default lease duration.
	LeaseDuration time.Duration

	// ClientID is the optional client identifier.
	ClientID []byte

	// VendorClass is the vendor class identifier.
	VendorClass string

	// UserClass is the user class information.
	UserClass string
}

// Clone returns a deep copy of the LeaseRequest.
func (r *LeaseRequest) Clone() *LeaseRequest {
	if r == nil {
		return nil
	}
	clone := &LeaseRequest{
		PoolID:        r.PoolID,
		Interface:     r.Interface,
		Hostname:      r.Hostname,
		RequestedIP:   r.RequestedIP,
		LeaseDuration: r.LeaseDuration,
		VendorClass:   r.VendorClass,
		UserClass:     r.UserClass,
	}
	if r.MAC != nil {
		clone.MAC = make(net.HardwareAddr, len(r.MAC))
		copy(clone.MAC, r.MAC)
	}
	if r.ClientID != nil {
		clone.ClientID = make([]byte, len(r.ClientID))
		copy(clone.ClientID, r.ClientID)
	}
	return clone
}

// Validate checks if the lease request is valid.
func (r *LeaseRequest) Validate() error {
	if r == nil {
		return ErrInvalidLeaseRequest
	}
	if len(r.MAC) == 0 {
		return ErrInvalidMAC
	}
	if r.PoolID == "" {
		return ErrPoolIDRequired
	}
	return nil
}

// Server defines the interface for a DHCP server.
// All API handlers (gRPC, REST) MUST use this interface to access DHCP
// functionality, ensuring proper abstraction and separation of concerns.
type Server interface {
	// Start starts the DHCP server on all configured interfaces.
	Start(ctx context.Context) error

	// Stop stops the DHCP server gracefully.
	Stop(ctx context.Context) error

	// Running returns true if the server is currently running.
	Running() bool

	// GetLease retrieves a lease by MAC address.
	// Returns the lease and true if found, nil and false otherwise.
	GetLease(mac net.HardwareAddr) (*Lease, bool)

	// GetLeaseByIP retrieves a lease by IP address.
	// Returns the lease and true if found, nil and false otherwise.
	GetLeaseByIP(ip netip.Addr) (*Lease, bool)

	// ListLeases returns all current leases.
	ListLeases() []*Lease

	// ReleaseLease releases a lease by MAC address.
	// Returns ErrLeaseNotFound if no lease exists for the MAC.
	ReleaseLease(mac net.HardwareAddr) error

	// Stats returns current server statistics.
	Stats() ServerStats
}
