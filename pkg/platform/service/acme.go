package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
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
func NewAcmeServer(ca ca.CertificateAuthority) *AcmeServer {
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
