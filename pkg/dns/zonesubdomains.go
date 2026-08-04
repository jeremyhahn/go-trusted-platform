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

package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// ErrZoneSubdomainsNoInternalServer is returned when ZoneSubdomains is enabled
// but no internal DNS server is configured.
type ErrZoneSubdomainsNoInternalServer struct{}

// Error implements the error interface.
func (ErrZoneSubdomainsNoInternalServer) Error() string {
	return "dns: zone-subdomains requires an internal DNS server to be configured"
}

// ErrZoneSubdomainsNoNetworkZones is returned when ZoneSubdomains is enabled
// but no network zones are provided.
type ErrZoneSubdomainsNoNetworkZones struct{}

// Error implements the error interface.
func (ErrZoneSubdomainsNoNetworkZones) Error() string {
	return "dns: zone-subdomains is enabled but no network zones were provided"
}

// InitNetworkZoneSubdomains ensures a DNS sub-zone exists for each network zone
// under the internal domain. Each sub-zone is named <networkzone>.<domain> and
// is authoritative for hosts registered within that network zone. This function
// is idempotent: zones that already exist in the datastore are left unchanged.
//
// The function only runs when Config.ZoneSubdomains is true. When false it
// returns nil immediately so callers do not need to guard the call site.
//
// This is a reflect-only DNS operation. No SDN policy is touched here.
// The sub-zones are pre-created at startup so that findZoneForQuery can
// locate them for queries like host.trusted.example.internal. before any
// device has registered.
func InitNetworkZoneSubdomains(
	ctx context.Context,
	cfg *Config,
	networkZones []string,
	zDAO dao.ZoneDAO,
	tenantID string,
) error {
	if cfg == nil || !cfg.ZoneSubdomains {
		return nil
	}
	if cfg.InternalServer == nil {
		return ErrZoneSubdomainsNoInternalServer{}
	}
	if len(networkZones) == 0 {
		return ErrZoneSubdomainsNoNetworkZones{}
	}

	// Derive the bare domain from the internal server zone name.
	// Zone names carry a trailing dot; strip it for string assembly.
	internalZoneName := cfg.InternalServer.Zone.Name
	domain := strings.TrimSuffix(internalZoneName, ".")

	for _, networkZone := range networkZones {
		if networkZone == "" {
			continue
		}
		if err := ensureNetworkZoneSubdomain(ctx, networkZone, domain, internalZoneName, zDAO, tenantID); err != nil {
			return err
		}
	}
	return nil
}

// ensureNetworkZoneSubdomain creates the DNS sub-zone for a single network zone
// if it does not already exist. The sub-zone name is <networkzone>.<domain>.
// Returns nil if the zone already exists.
func ensureNetworkZoneSubdomain(
	ctx context.Context,
	networkZone, domain, internalZoneName string,
	zDAO dao.ZoneDAO,
	tenantID string,
) error {
	subZoneName := fmt.Sprintf("%s.%s.", networkZone, domain)
	id := util.NewID([]byte(subZoneName))

	// Idempotent: skip if already present.
	existing, err := zDAO.Get(ctx, id)
	if err == nil && existing != nil {
		return nil
	}

	// Build the minimal sub-zone required for the DNS server to answer
	// queries within this network zone. The NS record delegates to the
	// same nameserver as the parent internal zone so the server remains
	// authoritative for the whole <domain> hierarchy.
	ns1 := fmt.Sprintf("ns1.%s", internalZoneName)
	zone := &entities.Zone{
		ID:          id,
		Name:        subZoneName,
		TenantID:    tenantID,
		TTL:         3600,
		Internal:    true,
		Description: fmt.Sprintf("Network zone subdomain for %s", networkZone),
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       subZoneName,
				MName:      ns1,
				RName:      fmt.Sprintf("hostmaster.%s", internalZoneName),
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     86400,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []*entities.NSRecord{
				{
					Name:  subZoneName,
					Value: ns1,
					TTL:   3600,
				},
			},
		},
	}

	if err := signZoneIfEnabled(zone); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("dns: failed to sign network-zone subdomain %s", subZoneName), Err: err}
	}

	if err := zDAO.Save(ctx, zone); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("dns: failed to save network-zone subdomain %s", subZoneName), Err: err}
	}

	return nil
}

// NetworkZoneSubdomainFQDN returns the zone-qualified FQDN for a host when
// zone_subdomains is enabled, or the standard FQDN otherwise. BMC names
// (those ending in "-bmc") are never zone-qualified per the management-zone
// convention in docs/architecture/reference-network.md.
//
// internalDomain should be the internal zone name without trailing dot.
// networkZone is the resolved network zone name (e.g. "trusted").
// host is the plain hostname label (e.g. "lab-node-1").
func NetworkZoneSubdomainFQDN(host, networkZone, internalDomain string) string {
	return fmt.Sprintf("%s.%s.%s", host, networkZone, internalDomain)
}

// IsBMCName reports whether a hostname label is a BMC alias. BMC names follow
// the convention <host>-bmc and are not zone-qualified.
func IsBMCName(host string) bool {
	return strings.HasSuffix(host, "-bmc")
}
