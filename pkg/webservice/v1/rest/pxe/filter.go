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

package pxe

import (
	"net/url"
	"strconv"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// filterState, filterMAC and filterVLAN are the ListDevices query
	// parameters, named after the PXEDeviceFilter fields they set.
	filterState = "state"
	filterMAC   = "mac_address"
	filterVLAN  = "vlan"

	// filterLimit and filterOffset page the matching devices.
	filterLimit  = "limit"
	filterOffset = "offset"

	// maxMACLength is the length of a colon-separated MAC address
	// ("00:11:22:33:44:55"); a longer prefix can match no device.
	maxMACLength = 17

	// minVLAN and maxVLAN bound an IEEE 802.1Q VLAN ID.
	minVLAN = 1
	maxVLAN = 4094
)

// deviceFilter reads the ListDevices query into a PXEDeviceFilter (#975).
// An absent or empty parameter leaves its field unset, which matches every
// device. state takes the ProvisioningState name with or without its
// PROVISIONING_STATE_ prefix ("quarantined" or
// "PROVISIONING_STATE_QUARANTINED"); mac_address an exact MAC or a prefix
// of one; vlan an 802.1Q VLAN ID; limit and offset a non-negative count.
func deviceFilter(query url.Values) (*platformv1.PXEDeviceFilter, error) {
	filter := &platformv1.PXEDeviceFilter{}

	if value := query.Get(filterState); value != "" {
		state, err := provisioningState(strings.TrimPrefix(strings.ToUpper(value), provisioningStatePrefix))
		if err != nil {
			return nil, &ErrInvalidDeviceFilter{Parameter: filterState, Value: value, Reason: "not a provisioning state"}
		}
		filter.State = state
	}

	if value := query.Get(filterMAC); value != "" {
		if !isMACPrefix(value) {
			return nil, &ErrInvalidDeviceFilter{Parameter: filterMAC, Value: value, Reason: "not a MAC address or a prefix of one"}
		}
		filter.MacAddress = value
	}

	if value := query.Get(filterVLAN); value != "" {
		vlan, err := strconv.ParseUint(value, 10, 16)
		if err != nil || vlan < minVLAN || vlan > maxVLAN {
			return nil, &ErrInvalidDeviceFilter{Parameter: filterVLAN, Value: value, Reason: "not a VLAN ID between 1 and 4094"}
		}
		filter.Vlan = uint32(vlan)
	}

	var err error
	if filter.Limit, err = pageBound(query, filterLimit); err != nil {
		return nil, err
	}
	if filter.Offset, err = pageBound(query, filterOffset); err != nil {
		return nil, err
	}

	return filter, nil
}

// pageBound reads the limit or offset parameter: a non-negative count, where
// zero (or absent) means no limit and no offset.
func pageBound(query url.Values, parameter string) (int32, error) {
	value := query.Get(parameter)
	if value == "" {
		return 0, nil
	}
	count, err := strconv.ParseInt(value, 10, 32)
	if err != nil || count < 0 {
		return 0, &ErrInvalidDeviceFilter{Parameter: parameter, Value: value, Reason: "not a non-negative count"}
	}
	return int32(count), nil
}

// isMACPrefix reports whether value is a colon-separated MAC address or a
// prefix of one: hex digits and colons, no longer than a full address.
func isMACPrefix(value string) bool {
	if len(value) > maxMACLength {
		return false
	}
	for _, c := range value {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex && c != ':' {
			return false
		}
	}
	return true
}
