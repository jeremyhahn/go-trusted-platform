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

// Package dns provides a client for DNS service operations.
package dns

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to DNS service operations.
type Client struct {
	grpc platformv1.DNSServiceClient
}

// NewClient creates a new DNS service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewDNSServiceClient(grpcConn),
	}, nil
}

// Zone Operations

// CreateZone creates a new DNS zone.
func (c *Client) CreateZone(ctx context.Context, req *platformv1.CreateZoneRequest) (*platformv1.Zone, error) {
	resp, err := c.grpc.CreateZone(ctx, req)
	if err != nil {
		return nil, &ErrCreateZoneFailed{Name: req.Name, Cause: err}
	}
	return resp.Zone, nil
}

// GetZone retrieves a DNS zone by name.
func (c *Client) GetZone(ctx context.Context, name string) (*platformv1.Zone, error) {
	resp, err := c.grpc.GetZone(ctx, &platformv1.GetZoneRequest{Name: name})
	if err != nil {
		return nil, &ErrGetZoneFailed{Name: name, Cause: err}
	}
	return resp.Zone, nil
}

// UpdateZone updates a DNS zone.
func (c *Client) UpdateZone(ctx context.Context, name string, ttl uint32, description string) (*platformv1.Zone, error) {
	resp, err := c.grpc.UpdateZone(ctx, &platformv1.UpdateZoneRequest{
		Name:        name,
		Ttl:         ttl,
		Description: description,
	})
	if err != nil {
		return nil, &ErrUpdateZoneFailed{Name: name, Cause: err}
	}
	return resp.Zone, nil
}

// DeleteZone deletes a DNS zone.
func (c *Client) DeleteZone(ctx context.Context, name string) error {
	_, err := c.grpc.DeleteZone(ctx, &platformv1.DeleteZoneRequest{Name: name})
	if err != nil {
		return &ErrDeleteZoneFailed{Name: name, Cause: err}
	}
	return nil
}

// ListZones lists DNS zones with optional filtering.
func (c *Client) ListZones(ctx context.Context, internalOnly, publicOnly bool, pagination *platformv1.PaginationRequest) ([]*platformv1.Zone, *common.PageResult, error) {
	resp, err := c.grpc.ListZones(ctx, &platformv1.ListZonesRequest{
		InternalOnly: internalOnly,
		PublicOnly:   publicOnly,
		Pagination:   pagination,
	})
	if err != nil {
		return nil, nil, &ErrListZonesFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Zones, pageResult, nil
}

// Record Operations

// AddRecord adds a record to a zone.
func (c *Client) AddRecord(ctx context.Context, zoneName string, record *platformv1.Record) (*platformv1.Zone, error) {
	resp, err := c.grpc.AddRecord(ctx, &platformv1.AddRecordRequest{
		ZoneName: zoneName,
		Record:   record,
	})
	if err != nil {
		return nil, &ErrAddRecordFailed{ZoneName: zoneName, Cause: err}
	}
	return resp.Zone, nil
}

// DeleteRecord deletes a record from a zone.
func (c *Client) DeleteRecord(ctx context.Context, zoneName string, recordType platformv1.RecordType, name string) (*platformv1.Zone, error) {
	resp, err := c.grpc.DeleteRecord(ctx, &platformv1.DeleteRecordRequest{
		ZoneName: zoneName,
		Type:     recordType,
		Name:     name,
	})
	if err != nil {
		return nil, &ErrDeleteRecordFailed{ZoneName: zoneName, Name: name, Cause: err}
	}
	return resp.Zone, nil
}

// UpdateRecord updates a record in a zone.
func (c *Client) UpdateRecord(ctx context.Context, zoneName string, oldRecord, newRecord *platformv1.Record) (*platformv1.Zone, error) {
	resp, err := c.grpc.UpdateRecord(ctx, &platformv1.UpdateRecordRequest{
		ZoneName:  zoneName,
		OldRecord: oldRecord,
		NewRecord: newRecord,
	})
	if err != nil {
		return nil, &ErrUpdateRecordFailed{ZoneName: zoneName, Cause: err}
	}
	return resp.Zone, nil
}

// ListRecords lists records in a zone.
func (c *Client) ListRecords(ctx context.Context, zoneName string, recordType platformv1.RecordType) ([]*platformv1.Record, error) {
	resp, err := c.grpc.ListRecords(ctx, &platformv1.ListRecordsRequest{
		ZoneName: zoneName,
		Type:     recordType,
	})
	if err != nil {
		return nil, &ErrListRecordsFailed{ZoneName: zoneName, Cause: err}
	}
	return resp.Records, nil
}

// DNSSEC Operations

// SignZone signs a zone with DNSSEC.
func (c *Client) SignZone(ctx context.Context, zoneName string) (*platformv1.Zone, error) {
	resp, err := c.grpc.SignZone(ctx, &platformv1.SignZoneRequest{ZoneName: zoneName})
	if err != nil {
		return nil, &ErrSignZoneFailed{ZoneName: zoneName, Cause: err}
	}
	return resp.Zone, nil
}

// GetDNSSECStatus retrieves the DNSSEC status for a zone.
func (c *Client) GetDNSSECStatus(ctx context.Context, zoneName string) (*platformv1.DNSSECStatus, error) {
	resp, err := c.grpc.GetDNSSECStatus(ctx, &platformv1.GetDNSSECStatusRequest{ZoneName: zoneName})
	if err != nil {
		return nil, &ErrGetDNSSECStatusFailed{ZoneName: zoneName, Cause: err}
	}
	return resp.Status, nil
}

// Resolution

// Resolve resolves a DNS query.
func (c *Client) Resolve(ctx context.Context, fqdn string, recordType platformv1.RecordType) ([]*platformv1.Record, bool, error) {
	resp, err := c.grpc.Resolve(ctx, &platformv1.ResolveRequest{
		Fqdn: fqdn,
		Type: recordType,
	})
	if err != nil {
		return nil, false, &ErrResolveFailed{FQDN: fqdn, Cause: err}
	}
	return resp.Records, resp.Authoritative, nil
}

// Registration

// Register registers a hostname with an IP address.
func (c *Client) Register(ctx context.Context, fqdn, ip string) (*platformv1.Zone, error) {
	resp, err := c.grpc.Register(ctx, &platformv1.RegisterRequest{
		Fqdn: fqdn,
		Ip:   ip,
	})
	if err != nil {
		return nil, &ErrRegisterFailed{FQDN: fqdn, Cause: err}
	}
	return resp.Zone, nil
}
