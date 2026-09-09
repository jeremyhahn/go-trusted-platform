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

package vpn

import (
	"context"
	"sort"
	"sync"
)

// MemoryLeaseStore is the in-memory lease projection the gateway keeps. It
// is also the unit-test store.
type MemoryLeaseStore struct {
	mu     sync.RWMutex
	leases map[LeaseID]*Lease
}

// NewMemoryLeaseStore returns an empty store.
func NewMemoryLeaseStore() *MemoryLeaseStore {
	return &MemoryLeaseStore{leases: make(map[LeaseID]*Lease)}
}

func (s *MemoryLeaseStore) Put(_ context.Context, lease *Lease) error {
	if lease == nil || lease.ID == "" {
		return &ErrInvalidRequest{Field: "lease", Reason: "nil or unidentified lease"}
	}
	cp := *lease
	s.mu.Lock()
	s.leases[lease.ID] = &cp
	s.mu.Unlock()
	return nil
}

func (s *MemoryLeaseStore) Get(_ context.Context, id LeaseID) (*Lease, error) {
	s.mu.RLock()
	l, ok := s.leases[id]
	s.mu.RUnlock()
	if !ok {
		return nil, &ErrLeaseNotFound{LeaseID: id}
	}
	cp := *l
	return &cp, nil
}

func (s *MemoryLeaseStore) Delete(_ context.Context, id LeaseID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.leases[id]; !ok {
		return &ErrLeaseNotFound{LeaseID: id}
	}
	delete(s.leases, id)
	return nil
}

func (s *MemoryLeaseStore) List(_ context.Context) ([]*Lease, error) {
	s.mu.RLock()
	out := make([]*Lease, 0, len(s.leases))
	for _, l := range s.leases {
		cp := *l
		out = append(out, &cp)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].IssuedAt.Before(out[j].IssuedAt)
	})
	return out, nil
}

func (s *MemoryLeaseStore) FindByDevice(_ context.Context, tenantID, deviceID string) (*Lease, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.leases {
		if l.TenantID == tenantID && l.DeviceID == deviceID {
			cp := *l
			return &cp, true, nil
		}
	}
	return nil, false, nil
}
