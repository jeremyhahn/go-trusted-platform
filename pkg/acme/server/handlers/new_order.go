package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
)

type NewOrderRequest struct {
	Identifiers []entities.ACMEIdentifier `yaml:"identifiers" json:"identifiers"`
	NotBefore   string                    `yaml:"not-before" json:"notBefore,omitempty"`
	NotAfter    string                    `yaml:"not-after" json:"notAfter,omitempty"`
}

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

	authorizationDAO, err := s.params.DAOFactory.ACMEAuthorizationDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create authorization DAO"))
		return
	}

	orderDAO, err := s.params.DAOFactory.ACMEOrderDAO(account.ID)
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

		if _, ok := acme.AuthzMap[id.Type]; !ok {
			writeError(w, acme.UnsupportedIdentifier("Unsupported authorization identifier"))
			return
		}

		domain := id.Value
		isWildcard := false
		if id.Type == acme.AuthzTypeDNS.String() {
			if strings.HasPrefix(domain, "*.") {
				isWildcard = true
				domain = strings.TrimPrefix(domain, "*.")
			}
			// Validate domain name
			if !isValidDomainName(domain) {
				writeError(w, acme.MalformedError("Invalid domain name", nil))
				return
			}
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

		// Create challenge
		challenges, err := s.createChallenges(account.ID, authzID, id)
		if err != nil {
			writeError(w, acme.ServerInternal("Failed to create authorization challenge"))
			return
		}

		// Save authorization
		authorization := &entities.ACMEAuthorization{
			ID:        authzID,
			OrderID:   orderID,
			AccountID: account.ID,
			Status:    acme.StatusPending,
			Expires:   time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			Identifier: entities.ACMEIdentifier{
				Type:  id.Type,
				Value: domain,
			},
			Challenges: challenges,
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

// Create challenges for the given account and authorization
func (s *RestService) createChallenges(accountID, authzID uint64, id entities.ACMEIdentifier) ([]entities.ACMEChallenge, error) {

	var challengeTypes []string
	ipAuthz := make([]string, 0)
	dnsAuthz := make([]string, 0)
	permIdAuthz := make([]string, 0)

	// Parse the configured challenge verifiers to get a list of
	// configured challenges.
	challengeVerifiers, err := acme.ParseConfiguredChallengeVerifiers(s.acmeConfig.Server.Challenges)
	if err != nil {
		return []entities.ACMEChallenge{}, err
	}

	// Organize challenges with into IP, DNS and permanent-identifier authorization types.
	for challengeType, _ := range challengeVerifiers {
		if acme.IsHTTPxChallenge(challengeType) {
			dnsAuthz = append(dnsAuthz, challengeType)
			continue
		}
		if acme.IsEnrollXChallenge(challengeType) {
			ipAuthz = append(ipAuthz, challengeType)
			continue
		}
		if _, ok := acme.AuthzDNSChallengeMap[challengeType]; ok {
			dnsAuthz = append(dnsAuthz, challengeType)
			continue
		}
		if _, ok := acme.AuthzPermanentIdChallengeMap[challengeType]; ok {
			permIdAuthz = append(permIdAuthz, challengeType)
			continue
		}
		return []entities.ACMEChallenge{}, fmt.Errorf("unsupported challenge type: %s", challengeType)
	}

	// Create a consolidated list of challenge types including both RFC
	// compliant challenges and those with custom dynamic port assignments.
	switch id.Type {
	case acme.AuthzTypeIP.String():
		challengeTypes = ipAuthz
	case acme.AuthzTypeDNS.String():
		challengeTypes = dnsAuthz
	case acme.AuthzTypePermanentIdentifier.String():
		challengeTypes = permIdAuthz
	default:
		return []entities.ACMEChallenge{}, fmt.Errorf("unsupported challenge type: %s", id.Type)
	}

	// Create a final list of challenge objects to return to the client
	challenges := make([]entities.ACMEChallenge, len(challengeTypes))
	for i, challengeType := range challengeTypes {

		token, err := GenerateToken()
		if err != nil {
			return []entities.ACMEChallenge{}, err
		}

		challengeID, err := GenerateID()
		if err != nil {
			return []entities.ACMEChallenge{}, err
		}

		challengeURL := fmt.Sprintf("%s/acme/challenge/%d", s.baseRESTURI, challengeID)

		challenges[i] = entities.ACMEChallenge{
			ID:              challengeID,
			Type:            challengeType,
			URL:             challengeURL,
			Status:          acme.StatusPending,
			Token:           string(token),
			AccountID:       accountID,
			AuthorizationID: authzID,
		}
	}

	return challenges, nil
}
