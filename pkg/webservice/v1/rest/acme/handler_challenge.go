package acme

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

func (s *RestService) ChallengeHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("ChallengeHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	if r.Method != http.MethodPost {
		writeError(w, acme.MalformedError("Method not allowed", nil))
		return
	}

	pieces := strings.Split(r.URL.Path, "/")
	sChallengeID := pieces[len(pieces)-1]
	if sChallengeID == "" {
		http.Error(w, "Authorization ID not provided", http.StatusBadRequest)
		return
	}

	challengeID, err := strconv.ParseUint(sChallengeID, 10, 64)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid challenge ID", nil))
		return
	}

	account, payload, err := s.parseKID(r)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse account key", nil))
		return
	}

	fmt.Println(string(payload))

	authzDAO, err := s.daoFactory.ACMEAuthorizationDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create authorization DAO"))
		return
	}

	orderDAO, err := s.daoFactory.ACMEOrderDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create order DAO"))
		return
	}

	var authz *entities.ACMEAuthorization
	var challenge *entities.ACMEChallenge

	pageQuery := datastore.NewPageQuery()
	pagerProcFunc := func(records []*entities.ACMEAuthorization) error {
	AUTHZ_LOOP:
		for _, _authz := range records {
			for _, _challenge := range _authz.Challenges {
				if _challenge.ID == challengeID && _authz.AccountID == _challenge.AccountID {
					authz = _authz
					challenge = &_challenge
					break AUTHZ_LOOP
				}
			}
		}
		return nil
	}
	if err := authzDAO.ForEachPage(pageQuery, pagerProcFunc, datastore.CONSISTENCY_LOCAL); err != nil {
		writeError(w, acme.ServerInternal("Failed to retrieve authorization"))
		return
	}

	// If the challenge is not in "pending" state, return it as is
	if challenge.Status != acme.StatusPending {
		challengeResponse(w, challenge)
		return
	}

	// Transition challenge to "processing"
	challenge.Status = acme.StatusProcessing
	if err := authzDAO.Save(authz); err != nil {
		writeError(w, acme.ServerInternal("Failed to update challenge status"))
		return
	}

	// Perform challenge validation
	validationSuccessful := s.validateChallenge(challenge, authz.Identifier, account)

	if validationSuccessful {
		// Validation succeeded
		challenge.Status = acme.StatusValid
		challenge.Validated = time.Now().Format(time.RFC3339)
		authz.Status = acme.StatusValid
		authz.Expires = time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	} else {
		// Validation failed
		challenge.Status = acme.StatusInvalid
		challenge.Error = acme.IncorrectResponse("Challenge validation failed")
		authz.Status = acme.StatusInvalid
		authz.Expires = ""
	}

	if err := authzDAO.Save(authz); err != nil {
		writeError(w, acme.ServerInternal("Failed to update authorization"))
		return
	}

	order, err := orderDAO.Get(authz.OrderID, s.consistencyLevel)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to retrieve order"))
		return
	}

	allAuthValid := true
	for _, authzURL := range order.Authorizations {

		pieces := strings.Split(authzURL, "/")
		sAuthzID := pieces[len(pieces)-1]

		authzID, err := strconv.ParseUint(sAuthzID, 10, 64)
		if err != nil {
			writeError(w, acme.MalformedError("Invalid authorization ID", nil))
			return
		}

		_authz, err := authzDAO.Get(authzID, s.consistencyLevel)
		if err != nil {
			writeError(w, acme.ServerInternal("Failed to retrieve authorization"))
			return
		}

		if _authz.Status != acme.StatusValid {
			order.Status = acme.StatusInvalid
			if err := orderDAO.Save(order); err != nil {
				writeError(w, acme.ServerInternal("Failed to update order status"))
				return
			}
			allAuthValid = false
			break
		}
	}

	if allAuthValid {
		order.Status = "ready"
		if err := orderDAO.Save(order); err != nil {
			writeError(w, acme.ServerInternal("Failed to update order status"))
			return
		}
	}

	challengeResponse(w, challenge)
}
