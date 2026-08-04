//go:build platform_p2p

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

// Package p2p provides libp2p-based peer-to-peer networking for gateway nodes.
// It wraps libp2p functionality to provide DHT-based peer discovery, NAT traversal,
// and secure peer connections for the go-trusted-platform network.
package p2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/multiformats/go-multiaddr"
)

// Default configuration values for libp2p node.
const (
	// DefaultListenPort is the default port for libp2p connections.
	DefaultListenPort = 4001

	// DefaultBootstrapTimeout is the timeout for bootstrap operations.
	DefaultBootstrapTimeout = 30 * time.Second

	// DefaultConnManagerLowWater is the minimum number of connections to maintain.
	DefaultConnManagerLowWater = 100

	// DefaultConnManagerHighWater is the maximum number of connections allowed.
	DefaultConnManagerHighWater = 400

	// DefaultConnManagerGracePeriod is the grace period for connection manager.
	DefaultConnManagerGracePeriod = time.Minute

	// DefaultRoutingTableRefreshPeriod is how often to refresh the DHT routing table.
	DefaultRoutingTableRefreshPeriod = 10 * time.Minute

	// MaxBootstrapPeers is the maximum number of bootstrap peers to return.
	MaxBootstrapPeers = 20
)

// NATStatus represents the NAT traversal status.
type NATStatus struct {
	// Reachability indicates the node's reachability status.
	Reachability string

	// PublicAddrs are the public addresses observed by peers.
	PublicAddrs []string
}

// NodeStatus represents the current status of the libp2p node.
type NodeStatus struct {
	// PeerID is the node's peer ID.
	PeerID peer.ID

	// ConnectedPeers is the number of connected peers.
	ConnectedPeers int

	// DHTRoutingTable is the number of peers in the DHT routing table.
	DHTRoutingTable int

	// NATStatus contains NAT traversal information.
	NATStatus NATStatus

	// ListenAddrs are the addresses the node is listening on.
	ListenAddrs []string

	// Uptime is how long the node has been running.
	Uptime time.Duration
}

// NodeConfig holds configuration for the libp2p node.
type NodeConfig struct {
	// PrivateKey is the node's private key for identity.
	// If nil, a new key will be generated.
	PrivateKey crypto.PrivKey

	// ListenAddrs are the multiaddrs to listen on.
	// If empty, defaults to /ip4/0.0.0.0/tcp/4001 and /ip6/::/tcp/4001.
	ListenAddrs []string

	// BootstrapPeers are the initial peers to connect to.
	BootstrapPeers []string

	// EnableRelayClient enables using relay nodes for NAT traversal.
	EnableRelayClient bool

	// EnableHolePunching enables direct connection attempts through NAT.
	EnableHolePunching bool

	// EnableAutoNAT enables automatic NAT detection.
	EnableAutoNAT bool

	// ConnManagerLowWater is the minimum connections to maintain.
	ConnManagerLowWater int

	// ConnManagerHighWater is the maximum connections allowed.
	ConnManagerHighWater int

	// DHTMode specifies the DHT mode (server, client, or auto).
	DHTMode DHTMode

	// Logger is the logger for the node.
	Logger *slog.Logger
}

// DHTMode represents the DHT operating mode.
type DHTMode int

const (
	// DHTModeAuto automatically determines the best DHT mode.
	DHTModeAuto DHTMode = iota

	// DHTModeServer runs the node as a DHT server (full participant).
	DHTModeServer

	// DHTModeClient runs the node as a DHT client (query only).
	DHTModeClient
)

// String returns a human-readable representation of the DHT mode.
func (m DHTMode) String() string {
	switch m {
	case DHTModeServer:
		return "server"
	case DHTModeClient:
		return "client"
	case DHTModeAuto:
		return "auto"
	default:
		return "unknown"
	}
}

// Validate validates the node configuration.
func (c *NodeConfig) Validate() error {
	if c == nil {
		return ErrConfigNil
	}

	// Set defaults
	if c.ConnManagerLowWater <= 0 {
		c.ConnManagerLowWater = DefaultConnManagerLowWater
	}
	if c.ConnManagerHighWater <= 0 {
		c.ConnManagerHighWater = DefaultConnManagerHighWater
	}
	if c.ConnManagerHighWater <= c.ConnManagerLowWater {
		c.ConnManagerHighWater = c.ConnManagerLowWater + 100
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}

	return nil
}

// Node wraps a libp2p host and DHT for peer-to-peer networking.
type Node struct {
	config   *NodeConfig
	host     host.Host
	dht      *dht.IpfsDHT
	routDisc *routing.RoutingDiscovery
	logger   *slog.Logger

	running   atomic.Bool
	startTime time.Time
	mu        sync.RWMutex
}

// NewNode creates a new libp2p node with the given configuration.
func NewNode(config *NodeConfig) (*Node, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Node{
		config: config,
		logger: config.Logger.With(slog.String("component", "p2p-node")),
	}, nil
}

// Start starts the libp2p node.
func (n *Node) Start(ctx context.Context) error {
	if n.running.Load() {
		return ErrAlreadyRunning
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Generate or use provided private key
	privKey := n.config.PrivateKey
	if privKey == nil {
		var err error
		privKey, _, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return &ErrNodeInitFailed{Component: "key_generation", Cause: err}
		}
	}

	// Build listen addresses
	listenAddrs := n.config.ListenAddrs
	if len(listenAddrs) == 0 {
		listenAddrs = []string{
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", DefaultListenPort),
			fmt.Sprintf("/ip6/::/tcp/%d", DefaultListenPort),
		}
	}

	// Convert string addresses to multiaddrs
	var maddrs []multiaddr.Multiaddr
	for _, addr := range listenAddrs {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return &ErrNodeInitFailed{Component: "listen_addr", Cause: err}
		}
		maddrs = append(maddrs, maddr)
	}

	// Create connection manager
	connMgr, err := connmgr.NewConnManager(
		n.config.ConnManagerLowWater,
		n.config.ConnManagerHighWater,
		connmgr.WithGracePeriod(DefaultConnManagerGracePeriod),
	)
	if err != nil {
		return &ErrNodeInitFailed{Component: "conn_manager", Cause: err}
	}

	// Build libp2p options
	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(maddrs...),
		libp2p.ConnectionManager(connMgr),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
		libp2p.NATPortMap(),
	}

	// Add optional features
	if n.config.EnableRelayClient {
		opts = append(opts, libp2p.EnableRelay())
	}
	if n.config.EnableHolePunching {
		opts = append(opts, libp2p.EnableHolePunching())
	}
	if n.config.EnableAutoNAT {
		opts = append(opts, libp2p.EnableNATService())
	}

	// Create the libp2p host
	h, err := libp2p.New(opts...)
	if err != nil {
		return &ErrNodeInitFailed{Component: "libp2p_host", Cause: err}
	}
	n.host = h

	// Create the DHT
	var dhtOpts []dht.Option
	switch n.config.DHTMode {
	case DHTModeServer:
		dhtOpts = append(dhtOpts, dht.Mode(dht.ModeServer))
	case DHTModeClient:
		dhtOpts = append(dhtOpts, dht.Mode(dht.ModeClient))
	default:
		dhtOpts = append(dhtOpts, dht.Mode(dht.ModeAuto))
	}

	kadDHT, err := dht.New(ctx, h, dhtOpts...)
	if err != nil {
		h.Close()
		return &ErrNodeInitFailed{Component: "kad_dht", Cause: err}
	}
	n.dht = kadDHT

	// Create routing discovery
	n.routDisc = routing.NewRoutingDiscovery(kadDHT)

	// Bootstrap the DHT
	if err := kadDHT.Bootstrap(ctx); err != nil {
		kadDHT.Close()
		h.Close()
		return &ErrNodeInitFailed{Component: "dht_bootstrap", Cause: err}
	}

	// Connect to bootstrap peers
	if len(n.config.BootstrapPeers) > 0 {
		if err := n.connectToBootstrapPeers(ctx); err != nil {
			n.logger.Warn("failed to connect to some bootstrap peers",
				slog.Any("error", err))
		}
	}

	n.startTime = time.Now()
	n.running.Store(true)

	n.logger.Info("libp2p node started",
		slog.String("peer_id", h.ID().String()),
		slog.Any("listen_addrs", h.Addrs()))

	return nil
}

// Stop stops the libp2p node.
func (n *Node) Stop(ctx context.Context) error {
	if !n.running.Load() {
		return ErrNotRunning
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	var errs []error

	// Close DHT first
	if n.dht != nil {
		if err := n.dht.Close(); err != nil {
			errs = append(errs, &ErrNodeStopFailed{Component: "dht", Cause: err})
		}
	}

	// Close host
	if n.host != nil {
		if err := n.host.Close(); err != nil {
			errs = append(errs, &ErrNodeStopFailed{Component: "host", Cause: err})
		}
	}

	n.running.Store(false)

	if len(errs) > 0 {
		return &ErrMultipleFailures{Errors: errs}
	}

	n.logger.Info("libp2p node stopped")
	return nil
}

// connectToBootstrapPeers connects to the configured bootstrap peers.
func (n *Node) connectToBootstrapPeers(ctx context.Context) error {
	var wg sync.WaitGroup
	var connectErrors []error
	var errMu sync.Mutex

	for _, addrStr := range n.config.BootstrapPeers {
		maddr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			errMu.Lock()
			connectErrors = append(connectErrors, err)
			errMu.Unlock()
			continue
		}

		peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			errMu.Lock()
			connectErrors = append(connectErrors, err)
			errMu.Unlock()
			continue
		}

		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
			timeoutCtx, cancel := context.WithTimeout(ctx, DefaultBootstrapTimeout)
			defer cancel()

			if err := n.host.Connect(timeoutCtx, pi); err != nil {
				errMu.Lock()
				connectErrors = append(connectErrors, err)
				errMu.Unlock()
				n.logger.Debug("failed to connect to bootstrap peer",
					slog.String("peer", pi.ID.String()),
					slog.Any("error", err))
			} else {
				n.logger.Debug("connected to bootstrap peer",
					slog.String("peer", pi.ID.String()))
			}
		}(*peerInfo)
	}

	wg.Wait()

	if len(connectErrors) == len(n.config.BootstrapPeers) {
		return &ErrBootstrapFailed{Cause: &MessageError{Msg: "failed to connect to any bootstrap peers"}}
	}

	return nil
}

// Host returns the underlying libp2p host.
func (n *Node) Host() host.Host {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.host
}

// DHT returns the underlying Kademlia DHT.
func (n *Node) DHT() *dht.IpfsDHT {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.dht
}

// PeerID returns the node's peer ID.
func (n *Node) PeerID() peer.ID {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.host == nil {
		return ""
	}
	return n.host.ID()
}

// ConnectedPeers returns the list of connected peer IDs.
func (n *Node) ConnectedPeers() []peer.ID {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.host == nil {
		return nil
	}
	return n.host.Network().Peers()
}

// IsConnected returns true if connected to the specified peer.
func (n *Node) IsConnected(peerID peer.ID) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.host == nil {
		return false
	}
	return n.host.Network().Connectedness(peerID) == network.Connected
}

// Connect connects to a peer by multiaddr.
func (n *Node) Connect(ctx context.Context, addrStr string) error {
	if !n.running.Load() {
		return ErrNotRunning
	}

	maddr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		return &ErrInvalidMultiaddr{Addr: addrStr, Cause: err}
	}

	peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return &ErrInvalidMultiaddr{Addr: addrStr, Cause: err}
	}

	n.mu.RLock()
	h := n.host
	n.mu.RUnlock()

	if h == nil {
		return ErrNotRunning
	}

	return h.Connect(ctx, *peerInfo)
}

// Disconnect disconnects from a peer.
func (n *Node) Disconnect(peerID peer.ID) error {
	if !n.running.Load() {
		return ErrNotRunning
	}

	n.mu.RLock()
	h := n.host
	n.mu.RUnlock()

	if h == nil {
		return ErrNotRunning
	}

	return h.Network().ClosePeer(peerID)
}

// FindPeers finds peers that provide a specific service/namespace.
func (n *Node) FindPeers(ctx context.Context, namespace string) (<-chan peer.AddrInfo, error) {
	if !n.running.Load() {
		return nil, ErrNotRunning
	}

	n.mu.RLock()
	routDisc := n.routDisc
	n.mu.RUnlock()

	if routDisc == nil {
		return nil, ErrNotRunning
	}

	return routDisc.FindPeers(ctx, namespace)
}

// Advertise advertises that this node provides a specific service/namespace.
func (n *Node) Advertise(ctx context.Context, namespace string) error {
	if !n.running.Load() {
		return ErrNotRunning
	}

	n.mu.RLock()
	routDisc := n.routDisc
	n.mu.RUnlock()

	if routDisc == nil {
		return ErrNotRunning
	}

	_, err := routDisc.Advertise(ctx, namespace)
	return err
}

// GetClosestPeers returns the closest peers to a given key.
func (n *Node) GetClosestPeers(ctx context.Context, key string) ([]peer.ID, error) {
	if !n.running.Load() {
		return nil, ErrNotRunning
	}

	n.mu.RLock()
	kadDHT := n.dht
	n.mu.RUnlock()

	if kadDHT == nil {
		return nil, ErrNotRunning
	}

	peers, err := kadDHT.GetClosestPeers(ctx, key)
	if err != nil {
		return nil, &ErrDHTOperationFailed{Operation: "GetClosestPeers", Key: key, Cause: err}
	}

	return peers, nil
}

// FindPeer finds a peer in the DHT by peer ID.
func (n *Node) FindPeer(ctx context.Context, id peer.ID) (peer.AddrInfo, error) {
	if !n.running.Load() {
		return peer.AddrInfo{}, ErrNotRunning
	}

	n.mu.RLock()
	kadDHT := n.dht
	n.mu.RUnlock()

	if kadDHT == nil {
		return peer.AddrInfo{}, ErrNotRunning
	}

	info, err := kadDHT.FindPeer(ctx, id)
	if err != nil {
		return peer.AddrInfo{}, &ErrDHTOperationFailed{Operation: "FindPeer", Key: id.String(), Cause: err}
	}

	return info, nil
}

// GetBootstrapPeers returns a list of connected peers suitable for bootstrapping.
func (n *Node) GetBootstrapPeers(limit int) []string {
	if !n.running.Load() {
		return nil
	}

	if limit <= 0 {
		limit = MaxBootstrapPeers
	}

	n.mu.RLock()
	h := n.host
	n.mu.RUnlock()

	if h == nil {
		return nil
	}

	connectedPeers := h.Network().Peers()
	peerStore := h.Peerstore()

	var bootstrapAddrs []string
	for _, p := range connectedPeers {
		if len(bootstrapAddrs) >= limit {
			break
		}

		addrs := peerStore.Addrs(p)
		for _, addr := range addrs {
			// Construct full p2p multiaddr
			fullAddr := fmt.Sprintf("%s/p2p/%s", addr.String(), p.String())
			bootstrapAddrs = append(bootstrapAddrs, fullAddr)
			if len(bootstrapAddrs) >= limit {
				break
			}
		}
	}

	return bootstrapAddrs
}

// RegisterNode registers a device as a DHT participant and returns bootstrap information.
func (n *Node) RegisterNode(ctx context.Context, deviceID string, ip net.IP, tier int) ([]byte, []string, error) {
	if !n.running.Load() {
		return nil, nil, ErrNotRunning
	}

	if deviceID == "" {
		return nil, nil, ErrDeviceIDRequired
	}

	n.mu.RLock()
	h := n.host
	kadDHT := n.dht
	n.mu.RUnlock()

	if h == nil || kadDHT == nil {
		return nil, nil, ErrNotRunning
	}

	// Use the peer ID as the node ID
	nodeID := []byte(h.ID())

	// Get bootstrap peers
	bootstrapPeers := n.GetBootstrapPeers(MaxBootstrapPeers)

	// Advertise that this device is part of the network
	namespace := fmt.Sprintf("/platform/device/%s", deviceID)
	if err := n.Advertise(ctx, namespace); err != nil {
		n.logger.Debug("failed to advertise device",
			slog.String("device_id", deviceID),
			slog.Any("error", err))
	}

	return nodeID, bootstrapPeers, nil
}

// Bootstrap provides bootstrap information for a joining node.
func (n *Node) Bootstrap(ctx context.Context, nodeID []byte) ([]string, string, int, error) {
	if !n.running.Load() {
		return nil, "", 0, ErrNotRunning
	}

	if len(nodeID) == 0 {
		return nil, "", 0, ErrNodeIDRequired
	}

	// Get bootstrap peers
	bootstrapPeers := n.GetBootstrapPeers(MaxBootstrapPeers)

	// Calculate bucket from node ID (XOR distance to our ID)
	bucket := n.calculateBucket(nodeID)

	// Determine region (default for now)
	region := "default"

	return bootstrapPeers, region, bucket, nil
}

// calculateBucket determines the K-bucket index for a node ID.
func (n *Node) calculateBucket(nodeID []byte) int {
	// Find the index of the first non-zero bit
	for i, b := range nodeID {
		if b != 0 {
			for j := 7; j >= 0; j-- {
				if b&(1<<j) != 0 {
					return i*8 + (7 - j)
				}
			}
		}
	}
	return 0
}

// GetStatus returns the current status of the node.
func (n *Node) GetStatus() *NodeStatus {
	n.mu.RLock()
	defer n.mu.RUnlock()

	status := &NodeStatus{
		NATStatus: NATStatus{
			Reachability: "unknown",
		},
	}

	if n.host == nil {
		return status
	}

	status.PeerID = n.host.ID()
	status.ConnectedPeers = len(n.host.Network().Peers())

	// Get listen addresses
	for _, addr := range n.host.Addrs() {
		status.ListenAddrs = append(status.ListenAddrs, addr.String())
	}

	// Get DHT routing table size
	if n.dht != nil {
		status.DHTRoutingTable = n.dht.RoutingTable().Size()
	}

	// Calculate uptime
	if !n.startTime.IsZero() {
		status.Uptime = time.Since(n.startTime)
	}

	// Get NAT status from observed addresses
	if len(n.host.Addrs()) > 0 {
		status.NATStatus.Reachability = "public"
		for _, addr := range n.host.Addrs() {
			status.NATStatus.PublicAddrs = append(status.NATStatus.PublicAddrs, addr.String())
		}
	}

	return status
}

// AddPeerAddress adds an address for a peer to the peerstore.
func (n *Node) AddPeerAddress(peerID peer.ID, addr multiaddr.Multiaddr) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.host == nil {
		return
	}

	n.host.Peerstore().AddAddr(peerID, addr, peerstore.PermanentAddrTTL)
}

// IsRunning returns true if the node is running.
func (n *Node) IsRunning() bool {
	return n.running.Load()
}
