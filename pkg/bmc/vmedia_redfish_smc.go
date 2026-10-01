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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// smcVirtualMediaPath is the Supermicro OEM Redfish virtual media CD slot.
// Modern Supermicro X11/X12/X13 boards expose CD/DVD virtual media here
// rather than via the standard /redfish/v1/Managers/{id}/VirtualMedia/{slot}
// collection used by Dell, HPE, and OpenBMC.
const smcVirtualMediaPath = "/redfish/v1/Managers/1/VM1/CfgCD"

// smcIsoConfigMountPath is the Supermicro OEM Action that actually attaches
// the ISO previously configured at smcVirtualMediaPath to the virtual CD
// drive. On X10 ATEN BMC firmware 4.0, a PATCH to CfgCD stores the Host/Path
// values but leaves the CD drive at Inserted=None until this action fires.
// Without this POST the host sees an empty virtual CD and boots past it to
// the next device in the boot order. Witnessed 2026-04-08 on node-02.
const smcIsoConfigMountPath = smcVirtualMediaPath + "/Actions/IsoConfig.Mount"

// smcIsoConfigUnmountPath is the inverse action. Supermicro names it
// "UnMount" with a capital M in the action identifier.
const smcIsoConfigUnmountPath = smcVirtualMediaPath + "/Actions/IsoConfig.UnMount"

// smcCD1Path is the actual DMTF VirtualMedia resource where the current
// Inserted / Image / ImageName state lives. CfgCD is only the Host/Path
// config shell; the real device state is on the VM1/CD1 resource.
const smcCD1Path = "/redfish/v1/Managers/1/VM1/CD1"

// smcLicenseSentinel is the literal substring Supermicro returns inside the
// extended-info MessageId when a feature is gated by the DCMS license.
const smcLicenseSentinel = "OemLicenseNotPassed"

// vmediaRedfishSmc is the Supermicro OEM Redfish virtual media backend.
// Supermicro accepts CIFS, HTTP, and HTTPS image URLs at the OEM CfgCD path
// and returns a structured Redfish error containing OemLicenseNotPassed
// when the BMC is missing the DCMS / SFT-DCMS-SINGLE license.
type vmediaRedfishSmc struct {
	c *redfishClient
}

func newVmediaRedfishSmc(c *redfishClient) *vmediaRedfishSmc {
	return &vmediaRedfishSmc{c: c}
}

// Name returns the stable identifier used in dispatch logs and errors.
func (b *vmediaRedfishSmc) Name() string { return "redfish-smc" }

// Supports reports support for HTTP, HTTPS, and CIFS image URLs.
// CIFS is the historically dominant transport for Supermicro virtual media.
func (b *vmediaRedfishSmc) Supports(spec *MediaSpec) bool {
	if spec == nil {
		return false
	}
	switch spec.Protocol {
	case MediaProtocolHTTP, MediaProtocolHTTPS, MediaProtocolCIFS:
		return true
	default:
		return false
	}
}

// smcCfgCDBody is the request body for Supermicro's OEM CfgCD endpoint.
// Field names match the JSON shape observed on X11/X12 firmware.
//
// WriteProtected is intentionally a *bool with omitempty: Supermicro X10
// ATEN BMC firmware 4.0 rejects PATCH requests that contain a
// WriteProtected property at all, returning HTTP 400 with the message
// "The property WriteProtected is not in the list of valid properties
// for the resource." (witnessed 2026-04-08 against an X10SDV-TP8F BMC
// running firmware 4.00.00 build 2023-08-10). Newer X11/X12 firmware
// accepts the field. Using *bool + omitempty lets callers explicitly
// opt-in by setting a non-nil value while the default of nil omits the
// field from the wire entirely, which is the only configuration that
// works across the X10/X11/X12 spread we currently support.
type smcCfgCDBody struct {
	Host           string `json:"Host,omitempty"`
	Path           string `json:"Path,omitempty"`
	Username       string `json:"Username,omitempty"`
	Password       string `json:"Password,omitempty" secret:"true"`
	Image          string `json:"Image,omitempty"`
	WriteProtected *bool  `json:"WriteProtected,omitempty"`
}

// Mount configures and attaches the virtual CD. On Supermicro X10/X11/
// X12 OEM firmware this is a three-step operation:
//
//  1. Idempotent unmount: POST IsoConfig.UnMount against any existing
//     attachment. If nothing is attached the BMC returns an error we
//     swallow; if something IS attached, leaving it in place would
//     cause the next IsoConfig.Mount to fail with
//     OemVmMountFail Error code: 11. Witnessed 2026-04-08 on node-02
//     when a previous orchestrator run crashed between install-log
//     success and its own unmount call, leaving the BMC with a stale
//     mount that blocked every subsequent Mount attempt.
//  2. PATCH the CfgCD resource with Host/Path/credentials. This
//     STORES the config; it does not attach media to the virtual
//     drive. CfgCD is the config shell, not the device.
//  3. POST the IsoConfig.Mount Action. This reads the stored config,
//     mounts the remote ISO (HTTP/HTTPS/CIFS), and flips the
//     Managers/1/VM1/CD1 device to Inserted=true. Without this POST,
//     the BMC returns success on the PATCH but the CD drive stays
//     empty, the host fails to boot from it, and falls through to
//     the next boot device — reproducing the "missing boot loader"
//     state we first hit on node-02.
func (b *vmediaRedfishSmc) Mount(ctx context.Context, spec *MediaSpec) error {
	// Step 1: best-effort idempotent unmount of any existing attachment.
	// Swallow errors — if nothing was mounted the BMC complains and
	// that's fine.
	_ = b.do(ctx, http.MethodPost, smcIsoConfigUnmountPath, map[string]any{})

	// Step 2: store config.
	body := smcBodyFromSpec(spec)
	if err := b.do(ctx, http.MethodPatch, smcVirtualMediaPath, body); err != nil {
		return err
	}
	// Step 3: actually attach the configured ISO to the virtual drive.
	// The action takes an empty body; all parameters come from the
	// CfgCD resource we just PATCHed.
	return b.do(ctx, http.MethodPost, smcIsoConfigMountPath, map[string]any{})
}

// Unmount detaches the virtual CD and clears the CfgCD slot. Also a
// two-step operation: first POST IsoConfig.UnMount to release the
// attachment, then PATCH CfgCD to clear Host/Path. If the drive is
// already empty the UnMount action may return an error which we
// swallow (idempotent unmount) before clearing the config.
//
// WriteProtected is intentionally omitted from the PATCH body — see
// the comment on smcCfgCDBody for why X10 BMC firmware rejects this
// property.
func (b *vmediaRedfishSmc) Unmount(ctx context.Context) error {
	// Step 1: best-effort detach. If nothing is mounted the BMC
	// returns a structured error we don't want to surface.
	_ = b.do(ctx, http.MethodPost, smcIsoConfigUnmountPath, map[string]any{})
	// Step 2: clear the stored config so a subsequent Mount starts
	// from a clean slate.
	body := smcCfgCDBody{Image: ""}
	return b.do(ctx, http.MethodPatch, smcVirtualMediaPath, body)
}

// Status reads the current Supermicro virtual CD state.
//
// The actual device state lives on the VM1/CD1 DMTF VirtualMedia resource;
// CfgCD is only the OEM config shell that stores Host/Path between Mount
// calls. We query CD1 first so callers see whether a CD is presently
// presented to the host BIOS. If CD1 is absent (older firmware that exposes
// only the OEM path) we fall back to CfgCD so Status remains best-effort
// across the X10/X11/X12 spread.
func (b *vmediaRedfishSmc) Status(ctx context.Context) (*VirtualMediaInfo, error) {
	info, err := b.statusFromPath(ctx, smcCD1Path)
	if err == nil {
		return info, nil
	}
	if !isVirtualMediaUnsupported(err) {
		return nil, err
	}
	// CD1 not present on this firmware; fall back to the OEM CfgCD config
	// shell. The Image field still reflects the most recent mount intent
	// even though it doesn't always track instantaneous device state.
	return b.statusFromPath(ctx, smcVirtualMediaPath)
}

// statusFromPath issues a Redfish GET against the supplied virtual-media
// path and decodes the standard Image/Inserted fields. 404 is normalised
// to ErrVirtualMediaUnsupported so the caller can fall through to a
// secondary path.
func (b *vmediaRedfishSmc) statusFromPath(ctx context.Context, path string) (*VirtualMediaInfo, error) {
	t := b.c.transport
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.BaseURL()+path, nil)
	if err != nil {
		return nil, ErrRedfishRequest{Method: http.MethodGet, Path: path, Cause: err}
	}
	if err := t.applyAuth(req); err != nil {
		return nil, ErrRedfishRequest{Method: http.MethodGet, Path: path, Cause: err}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := t.HTTPClient().Do(req)
	if err != nil {
		return nil, ErrRedfishRequest{Method: http.MethodGet, Path: path, Cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrVirtualMediaUnsupported{
			Backend: b.Name(),
			Vendor:  "Supermicro",
			Reason:  "BMC does not expose " + path,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if licenseErr := smcDetectLicense(bodyBytes); licenseErr != nil {
			return nil, licenseErr
		}
		return nil, ErrRedfishRequest{
			Method:     http.MethodGet,
			Path:       path,
			StatusCode: resp.StatusCode,
			Message:    string(bodyBytes),
		}
	}
	var state struct {
		Image    string `json:"Image"`
		Inserted bool   `json:"Inserted"`
		Host     string `json:"Host"`
		Path     string `json:"Path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return nil, ErrRedfishRequest{Method: http.MethodGet, Path: path, Cause: err}
	}
	// X10 ATEN firmware exposes only Host + Path on the CfgCD shell —
	// it does not populate Image or Inserted. Treat a non-empty Host
	// (with a Path) as "mounted" so status reflects the operator's
	// intent post-PATCH instead of always reporting Mounted: false.
	imageURL := state.Image
	if imageURL == "" && state.Host != "" {
		// Reconstruct a usable URL from Host + Path. We don't know
		// the protocol the firmware chose, but http:// is the
		// default for unauthenticated mounts and what platformctl
		// uses for the BMC HTTP fetch in this codebase.
		imageURL = "http://" + state.Host + state.Path
	}
	mounted := state.Inserted || imageURL != ""
	return &VirtualMediaInfo{
		Mounted:   mounted,
		ImageURL:  imageURL,
		MediaType: "cd",
	}, nil
}

// isVirtualMediaUnsupported is true for ErrVirtualMediaUnsupported (any
// reason). Used by Status to decide whether to fall back to a secondary
// virtual-media path.
func isVirtualMediaUnsupported(err error) bool {
	var unsupported ErrVirtualMediaUnsupported
	return errors.As(err, &unsupported)
}

// do is the SMC-aware request helper. It mirrors redfishClient.doPATCH but
// inspects the response body for the OemLicenseNotPassed sentinel and the
// 404 marker, surfacing them as fall-through errors for the dispatcher.
func (b *vmediaRedfishSmc) do(ctx context.Context, method string, path string, body any) error {
	t := b.c.transport
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return ErrRedfishRequest{Method: method, Path: path, Cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, method, t.BaseURL()+path, bytes.NewReader(jsonBytes))
	if err != nil {
		return ErrRedfishRequest{Method: method, Path: path, Cause: err}
	}
	if err := t.applyAuth(req); err != nil {
		return ErrRedfishRequest{Method: method, Path: path, Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := t.HTTPClient().Do(req)
	if err != nil {
		return ErrRedfishRequest{Method: method, Path: path, Cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrVirtualMediaUnsupported{
			Backend: b.Name(),
			Vendor:  "Supermicro",
			Reason:  "BMC does not expose the OEM CfgCD endpoint",
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return ErrRedfishRequest{
				Method:     method,
				Path:       path,
				StatusCode: resp.StatusCode,
				Message:    resp.Status,
			}
		}
		if licenseErr := smcDetectLicense(bodyBytes); licenseErr != nil {
			return licenseErr
		}
		return ErrRedfishRequest{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Message:    string(bodyBytes),
		}
	}
	return nil
}

// smcDetectLicense scans a Redfish error body for the OemLicenseNotPassed
// sentinel and returns a typed ErrVirtualMediaLicenseRequired if present.
// It returns nil for any body that does not contain the sentinel.
func smcDetectLicense(body []byte) error {
	if !bytes.Contains(body, []byte(smcLicenseSentinel)) {
		return nil
	}
	return ErrVirtualMediaLicenseRequired{
		Vendor:  "Supermicro",
		License: "DCMS",
	}
}

// smcBodyFromSpec converts a MediaSpec into the Supermicro CfgCD request shape.
// HTTP and HTTPS specs use the Image field; CIFS specs are decomposed into
// Host/Path/Username/Password.
//
// WriteProtected is intentionally not propagated from the spec on this code
// path — Supermicro X10 BMC firmware rejects unknown properties (see the
// comment on smcCfgCDBody). CD virtual media is implicitly read-only on the
// BMC side, so omitting the field gives the same effective semantics on
// every supported firmware revision. If a future caller needs to assert
// write-protection explicitly for a writable medium type (USB, floppy)
// the call site can set body.WriteProtected directly to a non-nil bool.
func smcBodyFromSpec(spec *MediaSpec) smcCfgCDBody {
	body := smcCfgCDBody{
		Username: spec.Username,
		Password: spec.Password,
	}
	if spec.Protocol == MediaProtocolCIFS {
		host, path := splitCIFS(spec.URL)
		body.Host = host
		body.Path = path
		return body
	}
	// X10 ATEN BMC firmware (≤4.00) requires HTTP/HTTPS URLs to be
	// split into Host + Path and REJECTS PATCH bodies that contain
	// `Image` as an unknown property (witnessed 2026-05-18 against
	// node-02 BMC: "The property Image is not in the list of valid
	// properties for the resource."). X11+/X12 firmware accepts the
	// combined Image form and also tolerates Host+Path with Image
	// absent. Sending only Host+Path is therefore the lowest-common-
	// denominator shape that works on every supported revision.
	host, path := splitHTTPURL(spec.URL)
	body.Host = host
	body.Path = path
	return body
}

// splitHTTPURL extracts the (Host, Path) pair from an http:// or
// https:// URL. Supermicro X10 firmware's CfgCD endpoint expects
// these as separate fields. The Host is host:port verbatim; the
// Path is the URL path-and-query starting with "/". Returns ("", url)
// when parsing fails so the BMC surfaces its own error.
func splitHTTPURL(rawURL string) (string, string) {
	trimmed := rawURL
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(trimmed, prefix) {
			trimmed = trimmed[len(prefix):]
			slash := strings.IndexByte(trimmed, '/')
			if slash < 0 {
				return trimmed, "/"
			}
			return trimmed[:slash], trimmed[slash:]
		}
	}
	return "", rawURL
}

// splitCIFS extracts the server host and remote path from a CIFS/SMB URL.
// Input shapes: cifs://server/share/path/file.iso, smb://server/share/file.iso.
// Returns ("", url) when parsing fails so the BMC can surface its own error.
func splitCIFS(rawURL string) (string, string) {
	trimmed := rawURL
	for _, prefix := range []string{"cifs://", "smb://", "//"} {
		if strings.HasPrefix(trimmed, prefix) {
			trimmed = trimmed[len(prefix):]
			break
		}
	}
	idx := strings.Index(trimmed, "/")
	if idx < 0 {
		return trimmed, ""
	}
	return trimmed[:idx], trimmed[idx:]
}
