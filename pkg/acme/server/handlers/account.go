package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
)

// AccountRequest represents the structure of the incoming account update/deactivation request body.
type AccountRequest struct {
	Status  string   `json:"status,omitempty"`
	Contact []string `json:"contact,omitempty"`
}

func (s *RestService) AccountHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("AccountHandler", "method", r.Method, "url", r.URL)
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

	accountDAO, err := s.params.DAOFactory.ACMEAccountDAO()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create account DAO"))
		return
	}

	var accountRequest AccountRequest
	if err := json.Unmarshal(payload, &accountRequest); err != nil {
		writeError(w, acme.MalformedError("Invalid request payload", nil))
		return
	}

	if accountRequest.Status != "" {
		if accountRequest.Status == acme.StatusDeactivated {
			if account.Status == acme.StatusDeactivated {
				writeError(w, acme.MalformedError("Account is already deactivated", nil))
				return
			}
			account.Status = acme.StatusDeactivated
		} else {
			writeError(w, acme.MalformedError("Invalid status value", nil))
			return
		}
	}

	if accountRequest.Contact != nil {
		if err := validateContactURLs(accountRequest.Contact); err != nil {
			writeError(w, err)
			return
		}
		account.Contact = accountRequest.Contact
	}

	if err := accountDAO.Save(account); err != nil {
		writeError(w, acme.ServerInternal("Failed to update account"))
		return
	}

	s.respondWithAccount(w, account, http.StatusOK)
}
