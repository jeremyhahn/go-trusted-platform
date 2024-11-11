package handlers

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/server"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type NewAccountRequest struct {
	Contact                []string    `yaml:"contact" json:"contact,omitempty"`
	TermsOfServiceAgreed   bool        `yaml:"termsOfServiceAgreed" json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool        `yaml:"onlyReturnExisting" json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding interface{} `yaml:"externalAccountBinding" json:"externalAccountBinding,omitempty"`
}

func (s *RestService) NewAccountHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("NewAccountHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	var account *entities.ACMEAccount

	accountDAO, err := s.params.DAOFactory.ACMEAccountDAO()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create account DAO"))
		return
	}

	publicKey, payload, err := s.parseJWS(r)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse account key", nil))
		return
	}

	var req NewAccountRequest
	err = json.Unmarshal(payload, &req)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid JSON payload", nil))
		return
	}

	if err := validateContactURLs(req.Contact); err != nil {
		writeError(w, err)
		return
	}

	// contacts := make([]string, len(req.Contact))
	// for i, contact := range req.Contact {
	// 	email := strings.Replace(contact, "mailto:", "", 1)
	// 	contacts[i] = email
	// }

	serializedKey, err := s.keySerializer.Serialize(publicKey)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to serialize account key"))
		return
	}

	accountID := keystore.PublicKeyID(publicKey, s.keySerializer.Type())

	account, err = accountDAO.Get(accountID, s.consistencyLevel)
	if err == nil {
		// Account exists
		if req.OnlyReturnExisting {
			// Return existing account
			s.respondWithAccount(w, account, http.StatusOK)
			return
		} else {
			writeError(w, acme.AccountExistsError(
				acme.ErrAccountAlreadyExists.Error(), s.accountURL(account)))
			return
		}
	} else {
		if req.OnlyReturnExisting {
			writeError(w, acme.AccountDoesNotExist("Account does not exist"))
			return
		}
	}

	// Validate contact URLs
	if err := validateContactURLs(req.Contact); err != nil {
		writeError(w, err)
		return
	}

	// Handle externalAccountBinding if required
	if externalAccountRequired && req.ExternalAccountBinding == nil {
		writeError(w, acme.ExternalAccountRequired("External account binding is required"))
		return
	}

	// Create new account
	account = &entities.ACMEAccount{
		ID:                     accountID,
		Status:                 acme.StatusValid,
		Contact:                req.Contact,
		TermsOfServiceAgreed:   req.TermsOfServiceAgreed,
		ExternalAccountBinding: req.ExternalAccountBinding,
		Orders:                 fmt.Sprintf("%s/acme/orders", s.baseRESTURI),
		Key:                    string(serializedKey),
		CreatedAt:              time.Now(),
	}
	account.URL = s.accountURL(account)

	// Save account
	if err := accountDAO.Save(account); err != nil {
		writeError(w, acme.ServerInternal("Failed to save account"))
		return
	}

	// Respond with account details
	s.respondWithAccount(w, account, http.StatusCreated)
}

// Parse JWS extracts the public key and payload from a JWS request
// without expecting a reply nonce. This method is only used for new
// account registrations.
func (s *RestService) parseJWS(r *http.Request) (crypto.PublicKey, []byte, error) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	jwsString := strings.TrimSpace(string(body))
	jws, err := jose.ParseSigned(jwsString, server.AllowedJOSEAlgorithms)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, nil, errors.New("no signatures found in JWS")
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.JSONWebKey != nil && protectedHeader.KeyID != "" {
		return nil, nil, ErrKIDAndJWKNotAllowed
	}

	if protectedHeader.JSONWebKey == nil {
		return nil, nil, errors.New("JWK not found in JWS header")
	}

	if protectedHeader.KeyID != "" {
		return nil, nil, ErrKIDAndJWKNotAllowed
	}

	if !s.nonceStore.Exists(protectedHeader.Nonce) {
		return nil, nil, acme.BadNonce("Invalid or missing Replay-Nonce")
	}

	publicKey := protectedHeader.JSONWebKey.Key
	if publicKey == nil {
		return nil, nil, errors.New("public key extraction failed")
	}

	payload, err := jws.Verify(publicKey)
	if err != nil {
		return nil, nil, errors.New("invalid JWS signature")
	}

	return publicKey, payload, nil
}
