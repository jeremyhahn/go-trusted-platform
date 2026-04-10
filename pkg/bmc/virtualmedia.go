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
	"net/url"
	"strings"
)

// MediaProtocol identifies the transport protocol used to fetch a virtual media image.
type MediaProtocol string

const (
	// MediaProtocolHTTP serves the image over plain HTTP.
	MediaProtocolHTTP MediaProtocol = "http"

	// MediaProtocolHTTPS serves the image over HTTPS.
	MediaProtocolHTTPS MediaProtocol = "https"

	// MediaProtocolCIFS serves the image over an SMB/CIFS share.
	MediaProtocolCIFS MediaProtocol = "cifs"

	// MediaProtocolNFS serves the image over an NFS export.
	MediaProtocolNFS MediaProtocol = "nfs"
)

// validMediaProtocols is the recognized set of MediaProtocol values.
var validMediaProtocols = map[MediaProtocol]struct{}{
	MediaProtocolHTTP:  {},
	MediaProtocolHTTPS: {},
	MediaProtocolCIFS:  {},
	MediaProtocolNFS:   {},
}

// schemeToProtocol maps URL schemes to MediaProtocol values for inference.
var schemeToProtocol = map[string]MediaProtocol{
	"http":  MediaProtocolHTTP,
	"https": MediaProtocolHTTPS,
	"cifs":  MediaProtocolCIFS,
	"smb":   MediaProtocolCIFS,
	"nfs":   MediaProtocolNFS,
}

// IsValid reports whether p is a recognized MediaProtocol.
func (p MediaProtocol) IsValid() bool {
	_, ok := validMediaProtocols[p]
	return ok
}

// MediaSpec describes a virtual media image to be mounted on a BMC.
// The zero value is not valid; callers must populate URL and either set
// Protocol explicitly or let inferProtocol derive it from the URL scheme.
type MediaSpec struct {
	URL            string
	Protocol       MediaProtocol
	Username       string
	Password       string
	WriteProtected bool
}

// inferProtocol fills in Protocol from the URL scheme when Protocol is empty.
// It is also called by Validate to keep the two paths consistent.
func (s *MediaSpec) inferProtocol() error {
	if s.Protocol != "" {
		return nil
	}
	if s.URL == "" {
		return ErrVirtualMediaInvalidSpec{Field: "URL", Reason: "must not be empty"}
	}
	parsed, err := url.Parse(s.URL)
	if err != nil {
		return ErrVirtualMediaInvalidSpec{Field: "URL", Reason: "malformed: " + err.Error()}
	}
	scheme := strings.ToLower(parsed.Scheme)
	proto, ok := schemeToProtocol[scheme]
	if !ok {
		return ErrVirtualMediaInvalidSpec{Field: "URL", Reason: "unrecognized scheme: " + scheme}
	}
	s.Protocol = proto
	return nil
}

// Validate ensures the MediaSpec is structurally complete and self-consistent.
// It infers Protocol from the URL scheme if Protocol is empty, and otherwise
// verifies that the explicit Protocol matches the URL scheme.
func (s *MediaSpec) Validate() error {
	if s == nil {
		return ErrVirtualMediaInvalidSpec{Field: "spec", Reason: "must not be nil"}
	}
	if strings.TrimSpace(s.URL) == "" {
		return ErrVirtualMediaInvalidSpec{Field: "URL", Reason: "must not be empty"}
	}
	parsed, err := url.Parse(s.URL)
	if err != nil {
		return ErrVirtualMediaInvalidSpec{Field: "URL", Reason: "malformed: " + err.Error()}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		return ErrVirtualMediaInvalidSpec{Field: "URL", Reason: "missing scheme"}
	}
	inferred, ok := schemeToProtocol[scheme]
	if !ok {
		return ErrVirtualMediaInvalidSpec{Field: "URL", Reason: "unrecognized scheme: " + scheme}
	}
	if s.Protocol == "" {
		s.Protocol = inferred
		return nil
	}
	if !s.Protocol.IsValid() {
		return ErrVirtualMediaInvalidSpec{Field: "Protocol", Reason: "unrecognized: " + string(s.Protocol)}
	}
	if s.Protocol != inferred {
		return ErrVirtualMediaInvalidSpec{
			Field:  "Protocol",
			Reason: "does not match URL scheme " + scheme,
		}
	}
	return nil
}

// virtualMediaBackend is the internal interface implemented by each
// vendor-specific virtual media transport. The dispatcher in
// vmedia_dispatch.go iterates a fixed-order list of backends and selects
// the first one whose Supports() returns true and whose Mount() succeeds.
type virtualMediaBackend interface {
	// Name returns a stable identifier for logging and error reporting.
	Name() string

	// Supports reports whether this backend can handle the given spec.
	// A false return causes the dispatcher to skip the backend silently.
	Supports(spec *MediaSpec) bool

	// Mount inserts the media described by spec.
	Mount(ctx context.Context, spec *MediaSpec) error

	// Unmount ejects whatever media is currently inserted.
	Unmount(ctx context.Context) error

	// Status returns the current insertion state.
	Status(ctx context.Context) (*VirtualMediaInfo, error)
}
