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
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// vmediaRedfishStd is the standard DMTF Redfish virtual media backend.
// It exercises /redfish/v1/Managers/{id}/VirtualMedia/{slot} via the
// VirtualMedia.InsertMedia and VirtualMedia.EjectMedia actions, which is
// the path supported by the majority of compliant BMCs (Dell iDRAC,
// HPE iLO, OpenBMC, and many others).
type vmediaRedfishStd struct {
	c *redfishClient
}

func newVmediaRedfishStd(c *redfishClient) *vmediaRedfishStd {
	return &vmediaRedfishStd{c: c}
}

// Name returns the stable identifier used in dispatch logs and errors.
func (b *vmediaRedfishStd) Name() string { return "redfish-std" }

// Supports reports support for HTTP and HTTPS image URLs. CIFS and NFS
// are technically allowed by the spec but vary widely between vendors,
// so they are routed to the OEM backends instead.
func (b *vmediaRedfishStd) Supports(spec *MediaSpec) bool {
	if spec == nil {
		return false
	}
	return spec.Protocol == MediaProtocolHTTP || spec.Protocol == MediaProtocolHTTPS
}

// Mount inserts the media via VirtualMedia.InsertMedia.
func (b *vmediaRedfishStd) Mount(ctx context.Context, spec *MediaSpec) error {
	c := b.c
	if err := c.ensureDiscovered(ctx); err != nil {
		return err
	}
	vmPath := c.getVirtualMediaPath()
	if vmPath == "" {
		return ErrVirtualMediaUnsupported{
			Backend: b.Name(),
			Vendor:  "DMTF",
			Reason:  "BMC did not advertise a VirtualMedia collection",
		}
	}
	cdPath, err := c.discoverVirtualMediaCD(ctx, vmPath)
	if err != nil {
		return err
	}
	var vm redfishVirtualMedia
	if err := c.doGET(ctx, cdPath, &vm); err != nil {
		return err
	}
	insertPath := vm.Actions.InsertMedia.ODataID
	if insertPath == "" {
		insertPath = cdPath + "/Actions/VirtualMedia.InsertMedia"
	}
	body := redfishInsertMediaBody{Image: spec.URL}
	if err := c.doPOST(ctx, insertPath, body, nil); err != nil {
		return b.maybeTranslateOEMFallback(err, "InsertMedia",
			"firmware does not support standard Redfish virtual media insert")
	}
	return nil
}

// Unmount ejects the currently inserted media via VirtualMedia.EjectMedia.
//
// An empty VirtualMedia collection is treated as success: on X10 hardware
// the IPMI eject path runs first and clears the collection out from
// under us, so the subsequent Redfish probe finds zero members. The
// post-state is the desired one (no media mounted), so reporting an
// error here would falsely flag every successful unmount as a failure.
func (b *vmediaRedfishStd) Unmount(ctx context.Context) error {
	c := b.c
	if err := c.ensureDiscovered(ctx); err != nil {
		return err
	}
	vmPath := c.getVirtualMediaPath()
	if vmPath == "" {
		return ErrVirtualMediaUnsupported{
			Backend: b.Name(),
			Vendor:  "DMTF",
			Reason:  "BMC did not advertise a VirtualMedia collection",
		}
	}
	cdPath, err := c.discoverVirtualMediaCD(ctx, vmPath)
	if err != nil {
		var emptyErr ErrRedfishEmptyCollection
		if errors.As(err, &emptyErr) && emptyErr.Resource == "VirtualMedia" {
			return nil
		}
		return err
	}
	var vm redfishVirtualMedia
	if err := c.doGET(ctx, cdPath, &vm); err != nil {
		return err
	}
	ejectPath := vm.Actions.EjectMedia.ODataID
	if ejectPath == "" {
		ejectPath = cdPath + "/Actions/VirtualMedia.EjectMedia"
	}
	if err := c.doPOST(ctx, ejectPath, struct{}{}, nil); err != nil {
		return b.maybeTranslateOEMFallback(err, "EjectMedia",
			"firmware does not support standard Redfish virtual media eject")
	}
	return nil
}

// maybeTranslateOEMFallback translates a 404 from the standard DMTF Redfish
// vmedia action into ErrVirtualMediaUnsupported when the resolved hardware
// Quirk advertises VmediaRedfishOEMFallback. The dispatch layer treats the
// "unsupported" signal as a cue to fall through to a vendor OEM backend.
//
// On vendors that do not advertise the OEM-fallback signal (DMTF-compliant
// BMCs such as Dell iDRAC and HPE iLO), the original error propagates
// unchanged — a 404 there is a real failure, not a known firmware quirk.
//
// action and reason describe the failed operation for diagnostic logs.
// Non-404 errors always propagate unchanged.
func (b *vmediaRedfishStd) maybeTranslateOEMFallback(err error, action, reason string) error {
	if err == nil {
		return nil
	}
	var reqErr ErrRedfishRequest
	if !errors.As(err, &reqErr) || reqErr.StatusCode != http.StatusNotFound {
		return err
	}
	if !b.c.resolveQuirk().VmediaRedfishOEMFallback {
		// Vendor does not request OEM fallback — propagate the 404
		// as a real error rather than silently translating it.
		return err
	}
	return ErrVirtualMediaUnsupported{
		Backend: b.Name(),
		Vendor:  "DMTF",
		Reason:  fmt.Sprintf("%s returned HTTP %d, %s", action, reqErr.StatusCode, reason),
	}
}

// Status returns the current insertion state from the VirtualMedia member.
func (b *vmediaRedfishStd) Status(ctx context.Context) (*VirtualMediaInfo, error) {
	c := b.c
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, err
	}
	vmPath := c.getVirtualMediaPath()
	if vmPath == "" {
		return &VirtualMediaInfo{Mounted: false}, nil
	}
	cdPath, err := c.discoverVirtualMediaCD(ctx, vmPath)
	if err != nil {
		return &VirtualMediaInfo{Mounted: false}, nil
	}
	var vm redfishVirtualMedia
	if err := c.doGET(ctx, cdPath, &vm); err != nil {
		return nil, err
	}
	mediaType := ""
	if len(vm.MediaTypes) > 0 {
		mediaType = strings.ToLower(vm.MediaTypes[0])
	}
	return &VirtualMediaInfo{
		Mounted:   vm.Inserted,
		ImageURL:  vm.Image,
		MediaType: mediaType,
	}, nil
}
