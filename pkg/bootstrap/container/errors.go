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

package container

import (
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// ErrManifestNotFound is returned when the manifest file does not exist.
type ErrManifestNotFound struct {
	Path string
}

func (e ErrManifestNotFound) Error() string {
	return fmt.Sprintf("container: manifest not found: %s", e.Path)
}

// ErrMACNotInManifest is returned when a MAC address is not found in the manifest.
type ErrMACNotInManifest struct {
	MAC string
}

func (e ErrMACNotInManifest) Error() string {
	return fmt.Sprintf("container: MAC %s not in manifest", e.MAC)
}

// Is makes a MAC the manifest does not carry the device lookup's
// "not found" (ipxe.ErrDeviceNotFound): the client falls through to its
// architecture's default entry.
func (e ErrMACNotInManifest) Is(target error) bool {
	return target == ipxe.ErrDeviceNotFound
}

// ErrServerStartFailed is returned when the bootstrap server fails to start.
type ErrServerStartFailed struct {
	Cause error
}

func (e ErrServerStartFailed) Error() string {
	return fmt.Sprintf("container: server start failed: %v", e.Cause)
}

func (e ErrServerStartFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidServerConfig is returned when the server configuration is invalid.
type ErrInvalidServerConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidServerConfig) Error() string {
	return fmt.Sprintf("container: invalid config: field %s: %s", e.Field, e.Reason)
}

// ErrManifestWrite is returned when writing the manifest to disk fails.
type ErrManifestWrite struct {
	Path  string
	Cause error
}

func (e ErrManifestWrite) Error() string {
	return fmt.Sprintf("container: failed to write manifest to %s: %v", e.Path, e.Cause)
}

func (e ErrManifestWrite) Unwrap() error {
	return e.Cause
}

// ErrManifestRead is returned when reading the manifest from disk fails.
type ErrManifestRead struct {
	Path  string
	Cause error
}

func (e ErrManifestRead) Error() string {
	return fmt.Sprintf("container: failed to read manifest from %s: %v", e.Path, e.Cause)
}

func (e ErrManifestRead) Unwrap() error {
	return e.Cause
}

// ErrManifestParse is returned when parsing the manifest YAML fails.
type ErrManifestParse struct {
	Path  string
	Cause error
}

func (e ErrManifestParse) Error() string {
	return fmt.Sprintf("container: failed to parse manifest from %s: %v", e.Path, e.Cause)
}

func (e ErrManifestParse) Unwrap() error {
	return e.Cause
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// ErrMediaSet is a media set the container cannot serve: an unreadable or
// inconsistent descriptor, a missing file, or a conflict between sets.
type ErrMediaSet struct {
	Path   string
	Reason string
	Err    error
}

func (e ErrMediaSet) Error() string {
	if e.Err != nil {
		return "bootstrap container: media set " + e.Path + ": " + e.Reason + ": " + e.Err.Error()
	}
	return "bootstrap container: media set " + e.Path + ": " + e.Reason
}

func (e ErrMediaSet) Unwrap() error { return e.Err }

// ErrUnknownMediaSet is a manifest entry that names a media set the
// container does not have, or whose architecture has no default set.
type ErrUnknownMediaSet struct {
	MAC          string
	MediaSet     string
	Architecture string
}

func (e ErrUnknownMediaSet) Error() string {
	if e.MediaSet != "" {
		return "bootstrap container: " + e.MAC + " boots media set " + e.MediaSet + ", which is not staged"
	}
	return "bootstrap container: " + e.MAC + " is " + e.Architecture + " and no media set is that architecture's default"
}

// ErrDisklessUnavailable is a diskless node whose media set was built without
// the diskless root (netboot media build without --diskless). Booting it
// anyway would install it to a disk it is not meant to have.
type ErrDisklessUnavailable struct {
	MAC      string
	MediaSet string
}

func (e ErrDisklessUnavailable) Error() string {
	return "bootstrap container: " + e.MAC + " boots diskless and media set " + e.MediaSet + " has no diskless root (rebuild the netboot media with --diskless)"
}

// ErrNotDisklessNBD is a request for the installed UKI of a node whose boot
// model is not diskless-nbd: it has no export, so no UKI there to serve.
type ErrNotDisklessNBD struct {
	MAC       string
	BootModel string
}

func (e ErrNotDisklessNBD) Error() string {
	model := e.BootModel
	if model == "" {
		model = "disk"
	}
	return "bootstrap container: " + e.MAC + " boots " + model + ", not diskless-nbd, and has no installed UKI to serve"
}

// ErrNBDCredentials is an NBD export server certificate or key that cannot
// be loaded. Without them no diskless-nbd node can attach its root.
type ErrNBDCredentials struct {
	CertFile string
	KeyFile  string
	Err      error
}

func (e ErrNBDCredentials) Error() string {
	return "bootstrap container: nbd certificate " + e.CertFile + " and key " + e.KeyFile + ": " + e.Err.Error()
}

func (e ErrNBDCredentials) Unwrap() error { return e.Err }

// ErrNBDServerAddress is an NBD listener address from which no address a
// diskless-nbd node can dial follows, so that node cannot be told where its
// root is.
type ErrNBDServerAddress struct {
	ListenAddr string
	Err        error
}

func (e ErrNBDServerAddress) Error() string {
	return "bootstrap container: nbd.listen_addr " + strconv.Quote(e.ListenAddr) + " names no address a diskless-nbd node can dial: " + e.Err.Error()
}

func (e ErrNBDServerAddress) Unwrap() error { return e.Err }

// ErrNetbootMedia is a netboot media build whose index is unreadable or
// names something the build does not hold.
type ErrNetbootMedia struct {
	Path   string
	Reason string
	Err    error
}

func (e ErrNetbootMedia) Error() string {
	if e.Err != nil {
		return "bootstrap container: netboot media " + e.Path + ": " + e.Reason + ": " + e.Err.Error()
	}
	return "bootstrap container: netboot media " + e.Path + ": " + e.Reason
}

func (e ErrNetbootMedia) Unwrap() error { return e.Err }

// ErrPayloadList is a payload list that cannot be read or used: a
// malformed line, an unsafe path, or a source that is missing or does not
// match its digest.
type ErrPayloadList struct {
	Line   int
	Reason string
	Err    error
}

func (e ErrPayloadList) Error() string {
	msg := "bootstrap container: payload list"
	if e.Line > 0 {
		msg += fmt.Sprintf(" line %d", e.Line)
	}
	msg += ": " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e ErrPayloadList) Unwrap() error { return e.Err }
