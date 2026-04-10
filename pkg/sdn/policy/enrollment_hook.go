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

package policy

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// EnrollmentEvent mirrors go-trusted-ca's OrderFinalizeHookContext
// This is a local type to avoid direct import dependency
type EnrollmentEvent struct {
	// Context is the request context
	Context context.Context

	// Certificate is the issued IDevID/certificate
	Certificate *x509.Certificate

	// CertificatePEM is the PEM-encoded certificate
	CertificatePEM []byte

	// ClientIP is the IP address of the enrolling device
	ClientIP string

	// IsTCGCSR indicates if this was a TCG-CSR-IDEVID enrollment
	IsTCGCSR bool

	// ProductModel is the device product model (only set if IsTCGCSR)
	ProductModel string

	// ProductSerial is the device serial number (only set if IsTCGCSR)
	ProductSerial string

	// PermanentIdentifier is the device permanent identifier
	PermanentIdentifier string
}

// EnrollmentHook is the function signature for enrollment callbacks
type EnrollmentHook func(event *EnrollmentEvent) error

// MACExtractor is a function type for extracting MAC addresses from IPs
// This allows for dependency injection during testing
type MACExtractor func(ipAddr string) string

// PendingActivation stores pending activation data
type PendingActivation struct {
	PortID      string
	Profile     *entities.DeviceProfile
	Certificate *x509.Certificate
	EnrolledAt  time.Time
}

// SDNEnrollmentHook handles SDN network transitions on device enrollment
type SDNEnrollmentHook struct {
	mu                 sync.RWMutex
	logger             *slog.Logger
	policyEngine       PolicyEngine
	profileDAO         devicedao.DeviceProfileDAO
	macToPort          map[string]string // MAC address to port ID mapping
	macExtractor       MACExtractor      // Pluggable MAC extraction function
	pendingActivations sync.Map          // serial -> *PendingActivation
}

// SDNEnrollmentHookConfig configures the enrollment hook
type SDNEnrollmentHookConfig struct {
	Logger       *slog.Logger
	PolicyEngine PolicyEngine
	ProfileDAO   devicedao.DeviceProfileDAO
	MACExtractor MACExtractor // Optional: defaults to ARP-based extraction
}

// NewSDNEnrollmentHook creates a new SDN enrollment hook
func NewSDNEnrollmentHook(config SDNEnrollmentHookConfig) (*SDNEnrollmentHook, error) {
	if config.PolicyEngine == nil {
		return nil, ErrInvalidPolicy
	}

	if config.ProfileDAO == nil {
		return nil, fmt.Errorf("profile DAO is required")
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	hook := &SDNEnrollmentHook{
		logger:       logger,
		policyEngine: config.PolicyEngine,
		profileDAO:   config.ProfileDAO,
		macToPort:    make(map[string]string),
	}

	// Use provided MAC extractor or default to ARP-based extraction
	if config.MACExtractor != nil {
		hook.macExtractor = config.MACExtractor
	} else {
		hook.macExtractor = hook.extractMACFromARPTable
	}

	return hook, nil
}

// PolicyEngine returns the underlying policy engine
func (h *SDNEnrollmentHook) PolicyEngine() PolicyEngine {
	return h.policyEngine
}

// OnEnrollmentComplete implements the enrollment callback
// This can be registered with go-trusted-ca's OrderFinalizeHookRegistry
func (h *SDNEnrollmentHook) OnEnrollmentComplete(event *EnrollmentEvent) error {
	if event == nil {
		return fmt.Errorf("enrollment event is nil")
	}

	if event.Certificate == nil {
		return ErrInvalidCertificate
	}

	h.logger.Info("processing enrollment completion",
		slog.String("client_ip", event.ClientIP),
		slog.String("serial", event.ProductSerial),
		slog.String("model", event.ProductModel),
		slog.Bool("is_tcg_csr", event.IsTCGCSR))

	// Try to find the device profile
	var profile *entities.DeviceProfile
	var err error

	// First try by serial number if available
	if event.ProductSerial != "" {
		profile, err = h.findProfileBySerial(event.ProductSerial)
		if err != nil {
			h.logger.Debug("profile not found by serial, trying MAC lookup",
				slog.String("serial", event.ProductSerial),
				slog.String("error", err.Error()))
		}
	}

	// If not found by serial, try by MAC address
	if profile == nil && event.ClientIP != "" {
		macAddr := h.macExtractor(event.ClientIP)
		if macAddr != "" {
			profile, err = h.findProfileByMAC(macAddr)
			if err != nil {
				h.logger.Warn("profile not found by MAC or serial",
					slog.String("mac", macAddr),
					slog.String("serial", event.ProductSerial),
					slog.String("error", err.Error()))
				return fmt.Errorf("device profile not found: %w", err)
			}
		} else {
			h.logger.Warn("unable to extract MAC address from client IP",
				slog.String("client_ip", event.ClientIP))
			return fmt.Errorf("unable to identify device: no MAC or serial match")
		}
	}

	if profile == nil {
		return fmt.Errorf("device profile not found for serial=%s", event.ProductSerial)
	}

	h.logger.Info("found device profile",
		slog.String("profile_name", profile.Name),
		slog.String("profile_id", fmt.Sprintf("%d", profile.ID)),
		slog.String("role", string(profile.Role)))

	// Extract MAC from IP for port lookup
	macAddr := h.macExtractor(event.ClientIP)
	if macAddr == "" {
		return fmt.Errorf("unable to extract MAC address from IP %s", event.ClientIP)
	}

	// Look up the port ID by MAC address
	portID, ok := h.GetPortByMAC(macAddr)
	if !ok {
		h.logger.Warn("port not registered for MAC address",
			slog.String("mac", macAddr))
		return fmt.Errorf("port not found for MAC address: %s", macAddr)
	}

	h.logger.Info("found port for device",
		slog.String("port_id", portID),
		slog.String("mac", macAddr))

	// Check current port state
	currentState, err := h.policyEngine.GetPortState(portID)
	if err != nil {
		h.logger.Debug("port state not found, will transition from provisioning",
			slog.String("port_id", portID))
	}

	// Transition from Provisioning to Enrolled
	// The device will remain in the enrollment VLAN until activated
	if err := h.policyEngine.SetPortState(portID, PortStateEnrolled); err != nil {
		h.logger.Error("failed to transition port to enrolled state",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to transition port to enrolled state: %w", err)
	}

	// Store pending activation data for later retrieval
	pending := &PendingActivation{
		PortID:      portID,
		Profile:     profile,
		Certificate: event.Certificate,
		EnrolledAt:  time.Now(),
	}
	h.pendingActivations.Store(event.ProductSerial, pending)

	h.logger.Info("device enrolled successfully, awaiting activation",
		slog.String("port_id", portID),
		slog.String("previous_state", currentState.String()),
		slog.String("new_state", PortStateEnrolled.String()),
		slog.String("serial", event.ProductSerial))

	return nil
}

// GetPendingActivation retrieves and removes a pending activation by serial
func (h *SDNEnrollmentHook) GetPendingActivation(serial string) (*PendingActivation, bool) {
	value, ok := h.pendingActivations.LoadAndDelete(serial)
	if !ok {
		return nil, false
	}
	pending, ok := value.(*PendingActivation)
	return pending, ok
}

// PeekPendingActivation retrieves a pending activation by serial without removing it.
// This is used by the device profile handler to return profile information.
func (h *SDNEnrollmentHook) PeekPendingActivation(serial string) (*PendingActivation, bool) {
	value, ok := h.pendingActivations.Load(serial)
	if !ok {
		return nil, false
	}
	pending, ok := value.(*PendingActivation)
	return pending, ok
}

// ActivateDevice transitions a device from Enrolled to Authorized
// This is called when the client explicitly requests activation via /device/activate
func (h *SDNEnrollmentHook) ActivateDevice(serial string) error {
	// Retrieve pending activation
	pending, ok := h.GetPendingActivation(serial)
	if !ok {
		return fmt.Errorf("no pending activation found for serial: %s", serial)
	}

	h.logger.Info("activating device",
		slog.String("serial", serial),
		slog.String("port_id", pending.PortID),
		slog.String("profile", pending.Profile.Name))

	// Build the production policy from the profile
	policy := h.buildPortPolicy(pending.Profile, pending.Certificate)
	if policy == nil {
		// Re-store the pending activation since we failed
		h.pendingActivations.Store(serial, pending)
		return fmt.Errorf("unable to build port policy from profile")
	}

	// Apply the production policy and transition to Authorized
	if err := h.policyEngine.ApplyPolicy(pending.PortID, policy); err != nil {
		// Re-store the pending activation since we failed
		h.pendingActivations.Store(serial, pending)
		h.logger.Error("failed to apply production policy during activation",
			slog.String("port_id", pending.PortID),
			slog.String("serial", serial),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to apply production policy: %w", err)
	}

	h.logger.Info("successfully activated device",
		slog.String("port_id", pending.PortID),
		slog.String("serial", serial),
		slog.Uint64("vlan", uint64(policy.VLAN)),
		slog.String("tenant_id", policy.TenantID))

	return nil
}

// RegisterPort maps a MAC address to a port ID for later lookup
func (h *SDNEnrollmentHook) RegisterPort(mac string, portID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Normalize MAC address to lowercase with colons
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	h.macToPort[mac] = portID

	h.logger.Debug("registered port mapping",
		slog.String("mac", mac),
		slog.String("port_id", portID))
}

// GetPortByMAC returns the port ID for a given MAC address
func (h *SDNEnrollmentHook) GetPortByMAC(mac string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Normalize MAC address
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	portID, ok := h.macToPort[mac]
	return portID, ok
}

// extractMACFromARPTable attempts to look up the MAC address from the ARP table
// Uses pure Go implementation by reading /proc/net/arp directly
// Returns empty string if not found. This is the default MAC extractor.
func (h *SDNEnrollmentHook) extractMACFromARPTable(ipAddr string) string {
	if ipAddr == "" {
		return ""
	}

	// Use the pure Go ARP table implementation
	table := arp.NewTable()
	mac, err := table.LookupMAC(ipAddr)
	if err != nil {
		h.logger.Debug("MAC address not found in ARP table",
			slog.String("ip", ipAddr),
			slog.String("error", err.Error()))
		return ""
	}

	h.logger.Debug("extracted MAC from ARP table",
		slog.String("ip", ipAddr),
		slog.String("mac", mac.String()))
	return mac.String()
}

// findProfileBySerial looks up a device profile by serial number
func (h *SDNEnrollmentHook) findProfileBySerial(serial string) (*entities.DeviceProfile, error) {
	if serial == "" {
		return nil, fmt.Errorf("serial number is empty")
	}

	// Search all profiles using ForEachPage
	var foundProfile *entities.DeviceProfile
	ctx := context.Background()

	err := h.profileDAO.ForEachPage(
		ctx,
		datastore.PageQuery{
			Page:     1,
			PageSize: 100,
		},
		func(result datastore.PageResult[*entities.DeviceProfile]) error {
			for _, profile := range result.Entities {
				if profile.MatchRules != nil && !profile.MatchRules.IsEmpty() {
					if profile.MatchRules.Matches("", serial, "") {
						h.logger.Debug("found profile by serial",
							slog.String("serial", serial),
							slog.String("profile", profile.Name))
						foundProfile = profile
						// Return stop iteration to stop
						return datastore.ErrStopIteration
					}
				}
			}
			return nil
		},
	)

	if foundProfile != nil {
		return foundProfile, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to search profiles: %w", err)
	}

	return nil, fmt.Errorf("no profile found for serial: %s", serial)
}

// findProfileByMAC looks up a device profile by MAC prefix
func (h *SDNEnrollmentHook) findProfileByMAC(mac string) (*entities.DeviceProfile, error) {
	if mac == "" {
		return nil, fmt.Errorf("MAC address is empty")
	}

	// Normalize MAC address
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	// Search all profiles using ForEachPage
	var foundProfile *entities.DeviceProfile
	ctx := context.Background()

	err := h.profileDAO.ForEachPage(
		ctx,
		datastore.PageQuery{
			Page:     1,
			PageSize: 100,
		},
		func(result datastore.PageResult[*entities.DeviceProfile]) error {
			for _, profile := range result.Entities {
				if profile.MatchRules != nil && !profile.MatchRules.IsEmpty() {
					if profile.MatchRules.Matches(mac, "", "") {
						h.logger.Debug("found profile by MAC",
							slog.String("mac", mac),
							slog.String("profile", profile.Name))
						foundProfile = profile
						// Return stop iteration to stop
						return datastore.ErrStopIteration
					}
				}
			}
			return nil
		},
	)

	if foundProfile != nil {
		return foundProfile, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to search profiles: %w", err)
	}

	return nil, fmt.Errorf("no profile found for MAC: %s", mac)
}

// buildPortPolicy creates a PortPolicy from a DeviceProfile's production network config
func (h *SDNEnrollmentHook) buildPortPolicy(profile *entities.DeviceProfile, cert *x509.Certificate) *PortPolicy {
	prodNet := profile.GetPostEnrollmentNetworkConfig()
	if prodNet == nil {
		h.logger.Warn("profile has no production network configuration",
			slog.String("profile", profile.Name))
		return nil
	}

	// Extract tenant ID from certificate (e.g., from Organization field)
	tenantID := "default"
	if len(cert.Subject.Organization) > 0 {
		tenantID = cert.Subject.Organization[0]
	}

	// Build the port policy
	policy := &PortPolicy{
		TenantID:    tenantID,
		VLAN:        prodNet.VLAN,
		Certificate: cert,
		ExpiresAt:   cert.NotAfter,
		IssuedAt:    time.Now(),
		Metadata: map[string]string{
			"profile_id":   fmt.Sprintf("%d", profile.ID),
			"profile_name": profile.Name,
			"device_role":  string(profile.Role),
		},
	}

	// Convert profile ACLs to policy ACLs
	if len(prodNet.ACLs) > 0 {
		policy.ACLs = make([]ACLRule, 0, len(prodNet.ACLs))
		for i, aclConfig := range prodNet.ACLs {
			if !aclConfig.IsValid() {
				h.logger.Warn("skipping invalid ACL rule",
					slog.Int("index", i),
					slog.String("profile", profile.Name))
				continue
			}

			// Build the flow match based on ACL config
			match := FlowMatch{
				VLANVid: prodNet.VLAN,
			}

			// Set source/destination IPs
			if aclConfig.SrcIP != "" && aclConfig.SrcIP != "any" {
				match.IPv4Src = aclConfig.SrcIP
			}
			if aclConfig.DstIP != "" && aclConfig.DstIP != "any" {
				match.IPv4Dst = aclConfig.DstIP
			}

			// Set protocol and ports
			switch aclConfig.Protocol {
			case "tcp":
				match.IPProto = 6 // TCP protocol number
				if aclConfig.SrcPort > 0 {
					match.TCPSrc = aclConfig.SrcPort
				}
				if aclConfig.DstPort > 0 {
					match.TCPDst = aclConfig.DstPort
				}
			case "udp":
				match.IPProto = 17 // UDP protocol number
				if aclConfig.SrcPort > 0 {
					match.UDPSrc = aclConfig.SrcPort
				}
				if aclConfig.DstPort > 0 {
					match.UDPDst = aclConfig.DstPort
				}
			case "icmp":
				match.IPProto = 1 // ICMP protocol number
			}

			// Build the flow action
			action := FlowAction{
				Type: FlowActionNormal, // Default to normal L2/L3 switching
			}

			switch aclConfig.Action {
			case "allow":
				action.Type = FlowActionAllow
			case "deny":
				action.Type = FlowActionDeny
			}

			policy.ACLs = append(policy.ACLs, ACLRule{
				Priority:    aclConfig.Priority,
				Match:       match,
				Action:      action,
				Description: fmt.Sprintf("Profile %s ACL rule %d", profile.Name, i),
			})
		}
	}

	h.logger.Debug("built port policy from profile",
		slog.String("profile", profile.Name),
		slog.Uint64("vlan", uint64(policy.VLAN)),
		slog.Int("acl_count", len(policy.ACLs)),
		slog.String("tenant_id", tenantID))

	return policy
}
