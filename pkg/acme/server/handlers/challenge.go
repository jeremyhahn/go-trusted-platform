package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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

	authzDAO, err := s.params.DAOFactory.ACMEAuthorizationDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create authorization DAO"))
		return
	}

	orderDAO, err := s.params.DAOFactory.ACMEOrderDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create order DAO"))
		return
	}

	var authz *entities.ACMEAuthorization
	var challenge *entities.ACMEChallenge

	pageQuery := datastore.NewPageQuery()
	pagerProcFunc := func(records []*entities.ACMEAuthorization) error {
		for _, _authz := range records {
			for _, _challenge := range _authz.Challenges {
				if _challenge.ID == challengeID && _authz.AccountID == _challenge.AccountID {
					authz = _authz
					challenge = &_challenge
					return nil
				}
			}
		}
		return acme.ErrChallengeNotFound
	}
	if err := authzDAO.ForEachPage(pageQuery, pagerProcFunc, datastore.ConsistencyLevelLocal); err != nil {
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
	var validationSuccessful bool

	pubKey, err := keystore.Deserialize(account.Key)
	if err != nil {
		challenge.Status = acme.StatusInvalid
		challenge.Error = acme.ServerInternal("Failed to decode account public key")
	}

	keyAuthorization, err := s.keySerializer.KeyAuthorization(challenge.Token, pubKey)
	if err != nil {
		challenge.Status = acme.StatusInvalid
		challenge.Error = acme.IncorrectResponse("Failed to compute key authorization")
	}

	// Parse the challenge type to extract the port number used by the challenge
	// selected by the client.
	_, challengePort, err := acme.ParseChallengeAsDynamicPortAssignment(challenge.Type)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse challenge type", nil))
		return
	}

	// Look up the challenge verifier from the challenge map and perform
	// the verification.
	challengeVerifierFunc, ok := s.challengeMap[challenge.Type]
	if !ok {
		challenge.Status = acme.StatusInvalid
		errmsg := fmt.Sprintf("Unsupported challenge type: %s", challenge.Type)
		challenge.Error = acme.MalformedError(errmsg, nil)
	} else {
		if err := challengeVerifierFunc(
			s.params.DNSService.Resolver(),
			s.ca,
			authz.Identifier.Value,
			challengePort,
			challenge.Token,
			keyAuthorization); err != nil {

			s.logger.Warn(
				"challenge verification failed",
				slog.String("error", err.Error()),
				slog.String("challenge", challenge.Type))
			challenge.Status = acme.StatusInvalid
			challenge.Error = acme.IncorrectResponse(err.Error())
		} else {
			validationSuccessful = true
		}
	}

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

	// Apply the updated challenge object to the Authorization
	for i, _challenge := range authz.Challenges {
		if _challenge.ID == challenge.ID {
			authz.Challenges[i] = *challenge
		}
	}

	// Save the updated Authorization
	if err := authzDAO.Save(authz); err != nil {
		writeError(w, acme.ServerInternal("Failed to update authorization"))
		return
	}

	// Look up the order associated with the authorization
	order, err := orderDAO.Get(authz.OrderID, s.consistencyLevel)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to retrieve order"))
		return
	}

	// Update the order status
	valid := true
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
			valid = false
			break
		}
	}
	if valid {
		order.Status = acme.StatusReady
		if err := orderDAO.Save(order); err != nil {
			writeError(w, acme.ServerInternal("Failed to update order status"))
			return
		}
	}

	challengeResponse(w, challenge)
}
