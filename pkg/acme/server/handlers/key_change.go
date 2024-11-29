package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// KeyChangeRequest represents the key change request body.
type KeyChangeRequest struct {
	AccountURL string          `json:"account"` // The account URL
	OldKey     keystore.KeyMap `json:"oldKey"`  // The old key in JWK format
}

type NewKeyPayload struct {
	JWK string `json:"jwk"`
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

// KeyChangeHandler handles key-change requests according to RFC 8555 Section
// 7.3.5 Account Key Rollover.
func (s *RestService) KeyChangeHandler(w http.ResponseWriter, r *http.Request) {

	// Parse the account and outer JWS payload from the request
	account, outerPayload, err := s.parseKID(r)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	accountDAO, err := s.params.DAOFactory.ACMEAccountDAO()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create account DAO"))
		return
	}

	// (1) Validate the POST request belongs to a currently active account
	persistedAccount, err := accountDAO.Get(account.ID, s.consistencyLevel)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to retrieve account"))
		return
	}
	if persistedAccount.Status != acme.StatusValid {
		writeError(w, acme.Unauthorized("Invalid account"))
		return
	}

	oldKeyMap, err := keystore.ParseKeyMap(account.Key)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid new key", nil))
		return
	}

	oldJOSEAlgo, err := oldKeyMap.JOSESignatureAlgorithm()
	if err != nil {
		writeError(w, acme.MalformedError("Invalid new key", nil))
		return
	}

	// (2) Check that the payload of the JWS is a well-formed JWS object
	innerJWS, err := jose.ParseSigned(string(outerPayload), []jose.SignatureAlgorithm{oldJOSEAlgo})
	if err != nil {
		writeError(w, acme.MalformedError("Invalid outer JWS", nil))
		return
	}

	if len(innerJWS.Signatures) == 0 {
		writeError(w, acme.MalformedError("no signatures found within inner JWS", nil))
		return
	}

	protectedHeader := innerJWS.Signatures[0].Header

	// (3) Check that the JWS protected header of the inner JWS has a "jwk" field
	if protectedHeader.JSONWebKey == nil {
		writeError(w, acme.MalformedError("JWK not found in JWS header", nil))
		return
	}

	// (4) Check that the inner JWS verifies using the key in its "jwk" field
	publicKey := protectedHeader.JSONWebKey.Key
	if publicKey == nil {
		writeError(w, acme.MalformedError("public key not found in JWK", nil))
		return
	}
	innerPayload, err := innerJWS.Verify(publicKey)
	if err != nil {
		writeError(w, acme.Unauthorized("Failed to verify inner JWS signature"))
		return
	}

	// (5) Check that the payload of the inner JWS is a well-formed keyChange object
	var keyChangeReq KeyChangeRequest
	if err := json.Unmarshal(innerPayload, &keyChangeReq); err != nil {
		writeError(w, acme.MalformedError("Invalid inner payload", nil))
		return
	}

	// (6) Check that the "url" parameters of the inner and outer JWSs are the same
	outerJWS, err := jose.ParseSigned(string(outerPayload), []jose.SignatureAlgorithm{oldJOSEAlgo})
	if err != nil {
		writeError(w, acme.MalformedError("Invalid outer JWS", nil))
		return
	}
	outerProtectedHeader := outerJWS.Signatures[0].Header
	if outerProtectedHeader.ExtraHeaders["url"] != protectedHeader.ExtraHeaders["url"] {
		writeError(w, acme.MalformedError("inner and outer JWS URL parameters don't match", nil))
		return
	}

	// (7) Check that the "account" field of the keyChange object matches the old key's account
	if keyChangeReq.AccountURL != persistedAccount.URL {
		writeError(w, acme.MalformedError("Account URL does not match the KID in outer JWS", nil))
		return
	}

	// (8) Check that the "oldKey" field matches the account's current key
	if !oldKeyMap.Equal(keyChangeReq.OldKey) {
		writeError(w, acme.MalformedError("Old key does not match account's current key", nil))
		return
	}

	// (9) Check that no account exists whose account key is the same as the
	//    key in the "jwk" header parameter of the inner JWS.
	pieces := strings.Split(keyChangeReq.AccountURL, "/")
	sAccountID := pieces[len(pieces)-1]
	accountID, err := strconv.ParseUint(sAccountID, 10, 64)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid account URL", nil))
		return
	}
	_, err = accountDAO.Get(accountID, s.consistencyLevel)
	if err == nil {
		writeError(w, acme.MalformedError("New account key already exists", nil))
		return
	}

	// Serialize the new key and save it to the database
	newSerializedKey, err := s.keySerializer.Serialize(protectedHeader.JSONWebKey.Key)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to serialize new key"))
		return
	}

	account.Key = string(newSerializedKey)

	if err := accountDAO.Save(account); err != nil {
		writeError(w, acme.ServerInternal("Failed to update account"))
		return
	}

	// Respond with success
	response := KeyChangeResponse{Message: "Key-change completed successfully"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
