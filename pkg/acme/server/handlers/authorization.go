package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
)

func (s *RestService) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("AuthorizationHandler", "method", r.Method, "url", r.URL)
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

	fmt.Println(string(payload))

	pieces := strings.Split(r.URL.Path, "/")
	sAuthzID := pieces[len(pieces)-1]
	if sAuthzID == "" {
		http.Error(w, "Authorization ID not provided", http.StatusBadRequest)
		return
	}

	authzID, err := strconv.ParseUint(sAuthzID, 10, 64)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid authorization ID", nil))
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.authorizationGetHandler(w, r, account.ID, authzID)
	case http.MethodPost:
		s.authorizationPostHandler(w, r, account.ID, authzID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAuthorizationGet handles GET requests for an authorization.
func (s *RestService) authorizationGetHandler(
	w http.ResponseWriter, r *http.Request, accountID, authzID uint64) {

	authorizationDAO, err := s.params.DAOFactory.ACMEAuthorizationDAO(accountID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create account DAO"))
		return
	}

	authorization, err := authorizationDAO.Get(authzID, s.consistencyLevel)
	if err != nil {
		writeError(w, acme.MalformedError("Authorization not found", nil))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authorization)
}

// handleAuthorizationPost handles POST requests to respond to a challenge.
func (s *RestService) authorizationPostHandler(
	w http.ResponseWriter, r *http.Request, accountID, authzID uint64) {

	authorizationDAO, err := s.params.DAOFactory.ACMEAuthorizationDAO(accountID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create account DAO"))
		return
	}

	authz, err := authorizationDAO.Get(authzID, s.consistencyLevel)
	if err != nil {
		writeError(w, acme.MalformedError("Authorization not found", nil))
		return
	}

	if authz.AccountID != accountID {
		writeError(w, acme.Unauthorized("Unauthorized"))
		return
	}

	clientAuthz := struct {
		Identifier entities.ACMEIdentifier  `json:"identifier"`
		Status     string                   `json:"status"`
		Expires    string                   `json:"expires,omitempty"`
		Challenges []entities.ACMEChallenge `json:"challenges"`
		Wildcard   *bool                    `json:"wildcard,omitempty"`
	}{
		Identifier: authz.Identifier,
		Status:     authz.Status,
		Expires:    authz.Expires,
		Challenges: authz.Challenges,
	}

	if authz.Wildcard {
		clientAuthz.Wildcard = &authz.Wildcard
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clientAuthz)
}
