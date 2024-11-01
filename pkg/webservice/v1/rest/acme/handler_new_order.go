package acme

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

type NewOrderRequest struct {
	Identifiers []entities.ACMEIdentifier `yaml:"identifiers" json:"identifiers"`
	NotBefore   string                    `yaml:"not-before" json:"notBefore,omitempty"`
	NotAfter    string                    `yaml:"not-after" json:"notAfter,omitempty"`
}

// // Order statuses (for /new-order)
// const (
// 	OrderStatusPending    = "pending"    // Order has been created but not yet finalized
// 	OrderStatusReady      = "ready"      // Challenges have been completed, and CSR can be submitted
// 	OrderStatusProcessing = "processing" // Order is being processed (e.g., certificate is being issued)
// 	OrderStatusValid      = "valid"      // Order has been completed, and the certificate is issued
// 	OrderStatusInvalid    = "invalid"    // Order is invalid (e.g., failed challenges, expired order)
// )

func (s *RestService) NewOrderHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("NewOrderHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	account, payload, err := s.parseKID(r)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse account key", nil))
		return
	}

	var req NewOrderRequest

	// Parse the payload
	if err := json.Unmarshal(payload, &req); err != nil {
		errResp := acme.MalformedError("Invalid JSON payload", nil)
		writeError(w, errResp)
		return
	}

	authorizationDAO, err := s.daoFactory.ACMEAuthorizationDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create authorization DAO"))
		return
	}

	orderDAO, err := s.daoFactory.ACMEOrderDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create order DAO"))
		return
	}

	orderID, err := GenerateID()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to generate order ID"))
		return
	}

	orderURL := fmt.Sprintf("%s/acme/orders/%d", s.baseRESTURI, orderID)
	finalizeURL := fmt.Sprintf("%s/finalize", orderURL)

	// Validate identifiers
	authzURLs := []string{}
	for _, id := range req.Identifiers {

		if id.Type != "dns" && id.Type != "permanent-identifier" {
			writeError(w, acme.UnsupportedIdentifier("Only 'dns' or 'permanent-identifier' identifiers are supported"))
			return
		}

		domain := id.Value
		isWildcard := false
		if strings.HasPrefix(domain, "*.") {
			isWildcard = true
			domain = strings.TrimPrefix(domain, "*.")
		}

		// Validate domain name
		if !isValidDomainName(domain) {
			writeError(w, acme.MalformedError("Invalid domain name", nil))
			return
		}

		// Make sure a certificate for this domain doesn't already exist
		if s.ca.Issued(domain) {
			writeError(w, acme.Unauthorized("Domain already issued a certificate"))
			return
		}

		// Create authorization
		authzID, err := GenerateID()
		if err != nil {
			writeError(w, acme.ServerInternal("Failed to generate authorization ID"))
			return
		}
		authzURL := fmt.Sprintf("%s/acme/authz/%d", s.baseRESTURI, authzID)

		// challengeID, err := GenerateID()
		// if err != nil {
		// 	writeError(w, acme.ServerInternal("Failed to generate challenge ID"))
		// 	return
		// }
		// challengeURL := fmt.Sprintf("%s/acme/challenge/%d", s.baseRESTURI, challengeID)

		// token, err := GenerateToken()
		// if err != nil {
		// 	writeError(w, acme.ServerInternal("Failed to generate challenge token"))
		// 	return
		// }

		// challenge := entities.ACMEChallenge{
		// 	ID:              challengeID,
		// 	Type:            "http-01",
		// 	URL:             challengeURL,
		// 	Status:          acme.StatusPending,
		// 	Token:           string(token),
		// 	AccountID:       account.ID,
		// 	AuthorizationID: authzID,
		// }

		identifier := entities.ACMEIdentifier{Type: id.Type, Value: domain}

		// http01, err := s.createChallenge(account.ID, authzID, "http-01")
		// if err != nil {
		// 	writeError(w, acme.ServerInternal("Failed to create http-01 challenge"))
		// 	return
		// }

		// deviceAttest01, err := s.createChallenge(account.ID, authzID, "device-attest-01")
		// if err != nil {
		// 	writeError(w, acme.ServerInternal("Failed to create device-attest-01 challenge"))
		// 	return
		// }

		challenge, err := s.createChallenge(account.ID, authzID, id)
		if err != nil {
			writeError(w, acme.ServerInternal("Failed to create authorization challenge"))
			return
		}

		authorization := &entities.ACMEAuthorization{
			ID:         authzID,
			OrderID:    orderID,
			AccountID:  account.ID,
			Status:     acme.StatusPending,
			Expires:    time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			Identifier: identifier,
			Challenges: []entities.ACMEChallenge{challenge},
			Wildcard:   isWildcard,
			URL:        authzURL,
		}

		if err := authorizationDAO.Save(authorization); err != nil {
			writeError(w, acme.ServerInternal("Failed to save authorization"))
			return
		}

		authzURLs = append(authzURLs, authzURL)
	}

	order := &entities.ACMEOrder{
		ID:             orderID,
		AccountID:      account.ID,
		Status:         acme.StatusPending,
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Identifiers:    req.Identifiers,
		NotBefore:      req.NotBefore,
		NotAfter:       req.NotAfter,
		Authorizations: authzURLs,
		Finalize:       finalizeURL,
		URL:            orderURL,
	}

	if err := orderDAO.Save(order); err != nil {
		writeError(w, acme.ServerInternal("Failed to save order"))
		return
	}

	// Respond with the order object
	// w.Header().Set("Location", orderURL)
	w.WriteHeader(http.StatusCreated)
	s.orderResponse(w, order)
}

func (s *RestService) createChallenge(accountID, authzID uint64, id entities.ACMEIdentifier) (entities.ACMEChallenge, error) {

	challengeID, err := GenerateID()
	if err != nil {
		return entities.ACMEChallenge{}, err
	}

	challengeURL := fmt.Sprintf("%s/acme/challenge/%d", s.baseRESTURI, challengeID)

	token, err := GenerateToken()
	if err != nil {
		return entities.ACMEChallenge{}, err
	}

	challenge := entities.ACMEChallenge{
		ID:              challengeID,
		Type:            id.Type,
		URL:             challengeURL,
		Status:          acme.StatusPending,
		Token:           string(token),
		AccountID:       accountID,
		AuthorizationID: authzID,
	}

	return challenge, nil
}

// func (s *RestService) challengeByIdentifier(
// 	accountID uint64, identifer entities.ACMEIdentifier) (entities.ACMEChallenge, error) {

// 	switch identifer.Type {
// 	case "http-01":
// 		return s.createChallenge(accountID, identifier.ID, identifier.Type)

// 	default:
// 		return entities.ACMEChallenge{}, fmt.Errorf("unsupported challenge type: %s", identifier.Type)
// 	}
// }
