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
		return err
	}
	return nil
}

// Unmount ejects the currently inserted media via VirtualMedia.EjectMedia.
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
		// Supermicro X10 ATEN BMC returns 404 for the standard
		// EjectMedia action — signal fall-through so the SMC OEM
		// backend can handle the unmount instead.
		var reqErr ErrRedfishRequest
		if errors.As(err, &reqErr) && reqErr.StatusCode == http.StatusNotFound {
			return ErrVirtualMediaUnsupported{
				Backend: b.Name(),
				Vendor:  "DMTF",
				Reason:  fmt.Sprintf("EjectMedia returned HTTP %d, firmware does not support standard Redfish virtual media eject", reqErr.StatusCode),
			}
		}
		return err
	}
	return nil
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
