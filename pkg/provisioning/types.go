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

package provisioning

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"time"
)

// ProfileResponse mirrors the server's response for GET /device/profile.
// ProvisioningNetwork is the enrollment-phase network when the profile
// defines one; the server uses its VLAN as the fail-closed revert target
// for the physical switch move during activation.
type ProfileResponse struct {
	SerialNumber        string           `json:"serialNumber"`
	AdmittedNetwork     NetworkConfig    `json:"admittedNetwork"`
	ProvisioningNetwork *NetworkConfig   `json:"provisioningNetwork,omitempty"`
	ACLs                []ACLConfig      `json:"acls,omitempty"`
	RateLimit           *RateLimitConfig `json:"rateLimit,omitempty"`
}

// NetworkConfig defines the admitted-phase network configuration delivered to
// an enrolled device.
type NetworkConfig struct {
	VLAN     uint16   `json:"vlan"`
	UseDHCP  bool     `json:"useDHCP"`
	StaticIP string   `json:"staticIP,omitempty"`
	Gateway  string   `json:"gateway,omitempty"`
	DNS      []string `json:"dns,omitempty"`
}

// ACLConfig defines an access control list entry
type ACLConfig struct {
	Name     string            `json:"name"`
	Priority int               `json:"priority"`
	Match    map[string]string `json:"match"`
	Action   string            `json:"action"`
}

// RateLimitConfig defines rate limiting parameters
type RateLimitConfig struct {
	IngressMbps int `json:"ingressMbps"`
	EgressMbps  int `json:"egressMbps"`
}

// ActivateResponse mirrors the server's response for POST /device/activate
type ActivateResponse struct {
	Status         string    `json:"status"`
	VLAN           uint16    `json:"vlan"`
	TransitionedAt time.Time `json:"transitionedAt"`
}

// HeartbeatResponse mirrors the server's response for POST /device/heartbeat.
type HeartbeatResponse struct {
	DeviceID   uint64    `json:"device_id"`
	Serial     string    `json:"serial"`
	ReceivedAt time.Time `json:"received_at"`
}

// BootCertificateRequest is the body of POST /device/boot/certificate.
// Signature is the node's BootCertificateProofDigest over the identity and
// the connection's BootChannelNonce, made with its TPM-resident IDevID key.
type BootCertificateRequest struct {
	Identity  string `json:"identity"`
	Signature []byte `json:"signature"`
}

// BootCertificateResponse mirrors the server's response for
// POST /device/boot/certificate: the IDevID chain recorded for an identity
// at enrollment, which a diskless node fetches back each boot to present its
// TPM-resident IDevID key over mTLS. The control plane answers only a node
// that proved it holds the key the chain certifies.
type BootCertificateResponse struct {
	Identity    string `json:"identity"`
	IDevIDChain string `json:"idevidChain"`
}

// BootDeliveryRequest is the body of POST /device/boot. Evidence is the
// JSON-encoded quote evidence (base64 in JSON) every attestation transport
// carries, made over the connection's BootChannelNonce.
type BootDeliveryRequest struct {
	Evidence []byte `json:"evidence"`
}

// BootDeliveryResponse mirrors the server's response for POST /device/boot:
// the material a verified diskless node needs to run, all PEM.
type BootDeliveryResponse struct {
	Serial      string `json:"serial"`
	IDevIDChain string `json:"idevidChain"`
	// AttestCert is the IAK certificate recorded at enrollment.
	AttestCert string `json:"attestCert"`
	// CABundle is the platform CA chain (root and intermediates).
	CABundle string          `json:"caBundle"`
	Profile  ProfileResponse `json:"profile"`
	// PCRBaselineSource is "signed" or "tofu": what the boot quote was
	// compared against. PCRBaselineCaptured is true when this boot's quote
	// recorded the trust-on-first-use baseline.
	PCRBaselineSource   string `json:"pcrBaselineSource"`
	PCRBaselineCaptured bool   `json:"pcrBaselineCaptured"`
}

// ClientConfig holds configuration for the provisioning client.
// TLS 1.3 with certificate verification is always enforced.
type ClientConfig struct {
	// ServerURL is the base URL of the provisioning server (e.g., "https://server.example.com:8443")
	ServerURL string

	// Certificate is the client IDevID certificate for mTLS
	Certificate *x509.Certificate

	// PrivateKey is the private key for the IDevID certificate
	PrivateKey crypto.PrivateKey

	// CACertPool contains trusted CA certificates for server verification
	CACertPool *x509.CertPool

	// TLSCertificate optionally supplies the complete client certificate
	// chain (leaf plus intermediates) with its private key. When set it
	// is presented verbatim; Certificate/PrivateKey are then used only
	// for identity metadata. Without it the client presents the single
	// Certificate — which fails against a control plane that does not
	// already hold the issuing intermediate.
	TLSCertificate *tls.Certificate

	// Timeout is the HTTP client timeout
	Timeout time.Duration
}

// DefaultClientConfig returns a configuration with sensible defaults
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Timeout: 30 * time.Second,
	}
}
