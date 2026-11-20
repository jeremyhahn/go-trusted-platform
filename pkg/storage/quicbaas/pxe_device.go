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

package quicbaas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

const entityTypePXEDevice = "PXEDevice"

// pxeDeviceListPageSize is the page size List reads the datastore with.
const pxeDeviceListPageSize = 1000

// PXEDeviceStore keeps the PXE backend's device records in the deployment
// datastore (docs/SPEC.md:23, #2028). Each device is one PXEDevice entity
// holding the whole DeviceInfo as JSON: lifecycle state, retry count, event
// history and IDevID binding. Records live in the system shard (0), like
// zones: PXE devices are platform state, not tenant data.
type PXEDeviceStore struct {
	storage  Storage
	tenantID string
	logger   *logging.Logger
	shardID  uint64
}

var _ pxe.DeviceStore = (*PXEDeviceStore)(nil)

// NewPXEDeviceStore returns a DeviceStore over storage.
func NewPXEDeviceStore(storage Storage, tenantID string, logger *logging.Logger) (*PXEDeviceStore, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &PXEDeviceStore{storage: storage, tenantID: tenantID, logger: logger}, nil
}

// pxeDeviceEntityID maps a PXE device ID to the datastore's numeric ID
// (FNV-64a). List reads the device ID back from the record itself.
func pxeDeviceEntityID(deviceID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(deviceID))
	return h.Sum64()
}

// Put stores device under its ID, replacing any earlier record.
func (s *PXEDeviceStore) Put(ctx context.Context, device *pxe.DeviceInfo) error {
	if device == nil || device.ID == "" {
		return errors.New("pxe device store: device ID is empty")
	}
	data, err := json.Marshal(device)
	if err != nil {
		return fmt.Errorf("pxe device store: encode %s: %w", device.ID, err)
	}
	if err := s.storage.Put(ctx, entityTypePXEDevice, pxeDeviceEntityID(device.ID), data, s.shardID); err != nil {
		return fmt.Errorf("pxe device store: put %s: %w", device.ID, err)
	}
	return nil
}

// Delete removes the record of deviceID.
func (s *PXEDeviceStore) Delete(ctx context.Context, deviceID string) error {
	if err := s.storage.Delete(ctx, entityTypePXEDevice, pxeDeviceEntityID(deviceID), s.shardID); err != nil {
		return fmt.Errorf("pxe device store: delete %s: %w", deviceID, err)
	}
	return nil
}

// List returns every stored device. A record that does not decode is logged
// and skipped, so one bad record does not keep the backend from starting.
func (s *PXEDeviceStore) List(ctx context.Context) ([]*pxe.DeviceInfo, error) {
	// The pinned go-quicbaas v0.12.0-alpha embedded transport ignores the
	// page token: it returns every record in one response but keeps the
	// first batch's NextPageToken. So the walk stops on a token already
	// sent or a page larger than the page size, and dedupes by ID.
	var devices []*pxe.DeviceInfo
	seenIDs := make(map[string]struct{})
	sentTokens := make(map[string]struct{})
	pageToken := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("pxe device store: list: %w", err)
		}
		sentTokens[pageToken] = struct{}{}
		page, next, err := s.storage.List(ctx, entityTypePXEDevice, pxeDeviceListPageSize, pageToken, s.shardID)
		if err != nil {
			return nil, fmt.Errorf("pxe device store: list: %w", err)
		}
		for _, entity := range page {
			var device pxe.DeviceInfo
			if err := datastore.DecodeEntity(entity.Data, &device); err != nil {
				s.logger.Warn("Failed to decode PXE device", "id", entity.ID, "error", err)
				continue
			}
			if _, dup := seenIDs[device.ID]; dup {
				continue
			}
			seenIDs[device.ID] = struct{}{}
			devices = append(devices, &device)
		}
		if next == "" || uint64(len(page)) > pxeDeviceListPageSize {
			return devices, nil
		}
		if _, sent := sentTokens[next]; sent {
			return devices, nil
		}
		pageToken = next
	}
}
