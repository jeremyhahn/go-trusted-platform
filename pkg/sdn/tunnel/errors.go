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

package tunnel

import (
	"fmt"
	"strconv"
)

// ErrTunnelCreateFailed is returned when tunnel creation fails.
type ErrTunnelCreateFailed struct {
	Name  string
	Cause error
}

// Error implements the error interface.
func (e *ErrTunnelCreateFailed) Error() string {
	return fmt.Sprintf("tunnel: failed to create %q: %v", e.Name, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrTunnelCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrTunnelNotFound is returned when a tunnel does not exist.
type ErrTunnelNotFound struct {
	Name string
}

// Error implements the error interface.
func (e *ErrTunnelNotFound) Error() string {
	return fmt.Sprintf("tunnel: not found: %q", e.Name)
}

// ErrTunnelAlreadyExists is returned when a tunnel already exists with different config.
type ErrTunnelAlreadyExists struct {
	Name string
}

// Error implements the error interface.
func (e *ErrTunnelAlreadyExists) Error() string {
	return fmt.Sprintf("tunnel: already exists: %q", e.Name)
}

// ErrInvalidTunnelConfig is returned when tunnel configuration is invalid.
type ErrInvalidTunnelConfig struct {
	Name   string
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidTunnelConfig) Error() string {
	if e.Name == "" {
		return fmt.Sprintf("tunnel: invalid config: %s", e.Reason)
	}
	return fmt.Sprintf("tunnel: invalid config for %q: %s", e.Name, e.Reason)
}

// ErrTunnelRemoveFailed is returned when tunnel removal fails.
type ErrTunnelRemoveFailed struct {
	Name  string
	Cause error
}

// Error implements the error interface.
func (e *ErrTunnelRemoveFailed) Error() string {
	return fmt.Sprintf("tunnel: failed to remove %q: %v", e.Name, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrTunnelRemoveFailed) Unwrap() error {
	return e.Cause
}

// ErrTunnelStatusFailed is returned when querying tunnel status fails.
type ErrTunnelStatusFailed struct {
	Name  string
	Cause error
}

// Error implements the error interface.
func (e *ErrTunnelStatusFailed) Error() string {
	return fmt.Sprintf("tunnel: failed to get status for %q: %v", e.Name, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrTunnelStatusFailed) Unwrap() error {
	return e.Cause
}

// ErrTransportUnavailable is returned when a transport is not built into
// this binary — WireGuard under the fips build tag.
type ErrTransportUnavailable struct {
	Name      string
	Transport string
	Reason    string
}

func (e *ErrTransportUnavailable) Error() string {
	return "tunnel " + e.Name + ": transport " + e.Transport + " is unavailable: " + e.Reason
}

// ErrKeyProviderRequired is returned when a transport needs key material
// and the manager was built without a KeyProvider.
type ErrKeyProviderRequired struct {
	Name      string
	Transport string
}

func (e *ErrKeyProviderRequired) Error() string {
	return "tunnel " + e.Name + ": transport " + e.Transport + " requires a key provider"
}

// ErrKeyMaterial is returned when the key provider fails or returns material
// of the wrong length. The reference is named; the material never is.
type ErrKeyMaterial struct {
	Name   string
	KeyRef string
	Reason string
	Cause  error
}

func (e *ErrKeyMaterial) Error() string {
	msg := "tunnel " + e.Name + ": key " + e.KeyRef + ": " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ErrKeyMaterial) Unwrap() error {
	return e.Cause
}

// ErrXfrmReply is returned when the kernel's answer to an SA read cannot be
// decoded, so the installed SA cannot be compared with the wanted one.
type ErrXfrmReply struct {
	Spi    int
	Reason string
	Cause  error
}

func (e *ErrXfrmReply) Error() string {
	msg := "xfrm state spi 0x" + strconv.FormatUint(uint64(uint32(e.Spi)), 16) + ": " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ErrXfrmReply) Unwrap() error {
	return e.Cause
}

// ErrUplinkUnknown is returned when a tunnel names an uplink no
// UplinkManager knows, or the manager has no UplinkManager at all.
type ErrUplinkUnknown struct {
	Name   string
	Uplink string
}

func (e *ErrUplinkUnknown) Error() string {
	return "tunnel " + e.Name + ": uplink " + e.Uplink + " is not configured"
}

// ErrInvalidUplinkConfig is returned when an UplinkConfig fails validation.
type ErrInvalidUplinkConfig struct {
	Name   string
	Reason string
}

func (e *ErrInvalidUplinkConfig) Error() string {
	if e.Name == "" {
		return "invalid uplink config: " + e.Reason
	}
	return "invalid uplink config " + e.Name + ": " + e.Reason
}

// ErrUplinkNotFound is returned when an unmanaged uplink is referenced.
type ErrUplinkNotFound struct {
	Name string
}

func (e *ErrUplinkNotFound) Error() string {
	return "uplink " + e.Name + " is not managed"
}

// ErrUplinkOperationFailed wraps a netlink failure while programming an
// uplink's table or rules.
type ErrUplinkOperationFailed struct {
	Name      string
	Operation string
	Cause     error
}

func (e *ErrUplinkOperationFailed) Error() string {
	return "uplink " + e.Name + ": " + e.Operation + ": " + e.Cause.Error()
}

func (e *ErrUplinkOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrRekeyFailed wraps a failure while rotating an IPsec SA.
type ErrRekeyFailed struct {
	Name  string
	Cause error
}

func (e *ErrRekeyFailed) Error() string {
	return "tunnel " + e.Name + ": rekey failed: " + e.Cause.Error()
}

func (e *ErrRekeyFailed) Unwrap() error {
	return e.Cause
}

// ErrIPsecSweepFailed is returned when the manager cannot list or remove the
// stale ESP state an earlier incarnation installed. Op names the step.
type ErrIPsecSweepFailed struct {
	Op    string
	Cause error
}

func (e *ErrIPsecSweepFailed) Error() string {
	return "ipsec sweep: " + e.Op + ": " + e.Cause.Error()
}

func (e *ErrIPsecSweepFailed) Unwrap() error {
	return e.Cause
}

// ErrIPsecInventory is returned when the record of the ESP pairs the
// platform installed cannot be read or written. Op names the step.
type ErrIPsecInventory struct {
	Path  string
	Op    string
	Cause error
}

func (e *ErrIPsecInventory) Error() string {
	return "ipsec inventory " + e.Path + ": " + e.Op + ": " + e.Cause.Error()
}

func (e *ErrIPsecInventory) Unwrap() error {
	return e.Cause
}

// ErrIPsecForeignPolicy is returned when the policy installed at a key the
// tunnel's ESP pair needs is not one espPolicy builds (ownedPolicyShape):
// another installer's. It is neither adopted nor replaced.
type ErrIPsecForeignPolicy struct {
	Src, Dst string
	Dir      string
}

func (e *ErrIPsecForeignPolicy) Error() string {
	return "ipsec policy " + e.Src + " -> " + e.Dst + " " + e.Dir + " is another installer's"
}

// ErrIPsecForeignSA reports an SA at the key the platform installs under
// that is not of the shape it builds: another installer's, which the
// platform neither adopts nor replaces.
type ErrIPsecForeignSA struct {
	Dst string
	SPI int
}

func (e *ErrIPsecForeignSA) Error() string {
	return "ipsec SA " + e.Dst + " spi " + strconv.Itoa(e.SPI) + " is another installer's"
}

// ErrRekeyUnsupported is returned when Rekey is called on a tunnel whose
// transport has no key to rotate.
type ErrRekeyUnsupported struct {
	Name      string
	Transport string
}

func (e *ErrRekeyUnsupported) Error() string {
	return "tunnel " + e.Name + ": transport " + e.Transport + " has no key to rotate"
}

// ErrPeerInvalid is returned when a hub peer's public key or allowed
// prefixes cannot be programmed as given.
type ErrPeerInvalid struct {
	Name   string
	Reason string
}

func (e *ErrPeerInvalid) Error() string {
	return "tunnel " + e.Name + ": invalid peer: " + e.Reason
}

// ErrPeerConfigureFailed is returned when the kernel refused a hub peer
// change.
type ErrPeerConfigureFailed struct {
	Name  string
	Cause error
}

func (e *ErrPeerConfigureFailed) Error() string {
	return "tunnel " + e.Name + ": peer configuration failed: " + e.Cause.Error()
}

func (e *ErrPeerConfigureFailed) Unwrap() error { return e.Cause }

// ErrDeviceNotUp is returned when a hub or TUN operation needs the device
// and it has not been brought up, or has been taken down.
type ErrDeviceNotUp struct {
	Name string
}

func (e *ErrDeviceNotUp) Error() string {
	return "tunnel " + e.Name + ": device is not up"
}
