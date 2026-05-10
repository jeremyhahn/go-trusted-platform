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

package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
)

const (
	OrderStatusPending     = "pending"
	OrderStatusValid       = "valid"
	OrderStatusDeactivated = "deactivated"
	OrderStatusExpired     = "expired"
	OrderStatusRevoked     = "revoked"
)

type Order struct {
	ID          string
	Status      string
	Domain      string
	Certificate []byte
}

type Authorization struct {
	ID     string
	Status string
	Domain string
}

type AcmeServer struct {
	orders         map[string]Order
	authorizations map[string]Authorization
	nonces         map[string]struct{}
	mu             sync.Mutex
}

// NewAcmeServer creates a new instance of AcmeServer.
func NewAcmeServer(ca trustedca.CACertificateAuthority) *AcmeServer {
	return &AcmeServer{
		orders:         make(map[string]Order),
		authorizations: make(map[string]Authorization),
		nonces:         make(map[string]struct{}),
	}
}

func (s *AcmeServer) CreateOrder(domain string) (Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	orderID := generateID()
	order := Order{
		ID:     orderID,
		Status: OrderStatusPending,
		Domain: domain,
	}
	s.orders[orderID] = order
	return order, nil
}

func (s *AcmeServer) FetchOrder(orderID string) (Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order, exists := s.orders[orderID]
	if !exists {
		return Order{}, errors.New("order not found")
	}
	return order, nil
}

func (s *AcmeServer) FinalizeOrder(orderID string, csr []byte) (Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order, exists := s.orders[orderID]
	if !exists {
		return Order{}, errors.New("order not found")
	}
	order.Status = OrderStatusValid
	order.Certificate = csr // Simplified for example purposes
	s.orders[orderID] = order
	return order, nil
}

func (s *AcmeServer) FetchAuthorization(authzID string) (Authorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	authz, exists := s.authorizations[authzID]
	if !exists {
		return Authorization{}, errors.New("authorization not found")
	}
	return authz, nil
}

func (s *AcmeServer) DeactivateAuthorization(authzID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	authz, exists := s.authorizations[authzID]
	if !exists {
		return errors.New("authorization not found")
	}
	authz.Status = OrderStatusDeactivated
	s.authorizations[authzID] = authz
	return nil
}

func (s *AcmeServer) NewNonce() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nonce := generateNonce()
	s.nonces[nonce] = struct{}{}
	return nonce, nil
}

func (s *AcmeServer) RevokeCertificate(cert []byte, reason int) error {
	// Simplified for example purposes
	return nil
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
