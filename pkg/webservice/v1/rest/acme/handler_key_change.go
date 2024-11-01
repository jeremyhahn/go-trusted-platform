package acme

import (
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
)

// KeyChangeRequest represents the key change request body.
type KeyChangeRequest struct {
	AccountURL string `json:"account"` // The account URL
	OldKey     string `json:"oldKey"`  // The old key in JWK format
	NewKey     string `json:"newKey"`  // The new key in JWK format
}

// KeyChangeResponse represents the successful key change response.
type KeyChangeResponse struct {
	Message string `json:"message"`
}

// ErrorResponse represents an error response for the API.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// KeyChangeHandler handles key-change requests according to RFC 8555 Section 7.3.5.
func (s *RestService) KeyChangeHandler(w http.ResponseWriter, r *http.Request) {

	account, payload, err := s.parseKID(r)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var keyChangeReq KeyChangeRequest
	if err := json.Unmarshal(payload, &keyChangeReq); err != nil {
		writeError(w, acme.MalformedError("Invalid request body", nil))
		return
	}

	if account.Orders != keyChangeReq.AccountURL {
		writeError(w, acme.MalformedError("Account URL mismatch", nil))
		return
	}

	currentKeyMap, err := acme.ParseKeyMap(account.Key)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid current key", nil))
		return
	}

	oldKeyMap, err := acme.ParseKeyMap(keyChangeReq.OldKey)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid key", nil))
		return
	}

	if !currentKeyMap.Equals(oldKeyMap) {
		writeError(w, acme.Unauthorized("Old key does not match the current account key"))
		return
	}

	newKeyMap, err := acme.ParseKeyMap(keyChangeReq.NewKey)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid new key", nil))
		return
	}
	newKey, err := newKeyMap.String()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to generate new key"))
		return
	}
	account.Key = string(newKey)

	accountDAO, err := s.daoFactory.ACMEAccountDAO()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create account DAO"))
		return
	}
	if err := accountDAO.Save(account); err != nil {
		writeError(w, acme.ServerInternal("Failed to update account"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Key updated successfully"}`))
}
