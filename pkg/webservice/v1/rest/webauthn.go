package rest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

var (
	ErrInvalidOrganizationID = errors.New("invalid organization id")
	ErrUserAlreadyExists     = errors.New("user already registered")
	ErrInvalidUserIDHeader   = errors.New("invalid user id header")
	ErrInvalidUserID         = errors.New("invalid user")
)

type request struct {
	Email string `json:"username"`
}

type WebAuthnRestServicer interface {
	BeginRegistration(w http.ResponseWriter, r *http.Request)
	FinishRegistration(w http.ResponseWriter, r *http.Request)
	BeginLogin(w http.ResponseWriter, r *http.Request)
	FinishLogin(w http.ResponseWriter, r *http.Request)
	RegistrationStatus(w http.ResponseWriter, r *http.Request)
	middleware.AuthMiddleware
}

type WebAuthnRestService struct {
	logger              *logging.Logger
	jwtService          *jwt.Service
	userService         service.UserServicer
	registrationService service.RegistrationServicer
	responseWriter      response.HttpWriter
	webAuthn            *webauthn.WebAuthn
	WebAuthnRestServicer
}

func NewWebAuthnRestService(
	logger *logging.Logger,
	config *config.WebService,
	responseWriter response.HttpWriter,
	jwtService *jwt.Service,
	userService service.UserServicer,
	registrationService service.RegistrationServicer,
	sessionService service.WebAuthnSessionServicer) (WebAuthnRestServicer, error) {

	var displayName, id string
	var origins []string
	if config.WebAuthn != nil {
		// Use web service webauthn config
		if config.WebAuthn.RPDisplayName != "" {
			displayName = config.WebAuthn.RPDisplayName
		}
		if config.WebAuthn.RPID != "" {
			id = config.WebAuthn.RPID
		}
		if len(config.WebAuthn.RPOrigins) > 0 {
			origins = config.WebAuthn.RPOrigins
		}
	}
	// Use web service JWT and certificate values as defaults if
	// webauthn config isn't defined
	if displayName == "" {
		displayName = config.Certificate.Subject.CommonName
	}
	if id == "" {
		if config.JWT.Issuer != "" {
			id = config.JWT.Issuer
		} else {
			id = config.Certificate.Subject.CommonName
		}
	}
	if len(origins) == 0 {
		origins = []string{config.Certificate.Subject.CommonName}
	}
	wconfig := &webauthn.Config{
		RPDisplayName: displayName, // Display Name for your site
		RPID:          id,          // Generally the FQDN for your site
		RPOrigins:     origins,     // The origin URLs allowed for WebAuthn requests
		Debug:         config.Key.Debug,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,             // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for login sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,             // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for registration sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
			},
		},
	}

	logger.Debug("webauthn config", wconfig)

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		fmt.Println(err)
	}
	return &WebAuthnRestService{
		logger:              logger,
		jwtService:          jwtService,
		userService:         userService,
		registrationService: registrationService,
		responseWriter:      responseWriter,
		webAuthn:            webAuthn,
	}, nil
}

func (restService *WebAuthnRestService) BeginRegistration(w http.ResponseWriter, r *http.Request) {

	restService.logger.Debug("webauthn begin registration")

	type Username struct {
		Username string `json:"username"`
	}
	var u Username
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return
	}

	opts := make([]webauthn.RegistrationOption, 0)

	userID := util.NewID([]byte(u.Username))

	restService.logger.Debug("begin registration", slog.Uint64("userID", userID))

	user, err := restService.userService.Get(userID)
	if err != nil {
		if err == datastore.ErrRecordNotFound {
			user = entities.NewUser(u.Username)
		} else {
			restService.responseWriter.Error400(w, r, err)
			return
		}
	} else {
		restService.responseWriter.Error400(w, r, ErrUserAlreadyExists)
		return
		// for _, credential := range user.Credentials {
		// 	opts = append(opts,
		// 		webauthn.WithExclusions([]protocol.CredentialDescriptor{
		// 			{
		// 				CredentialID: credential.Descriptor().CredentialID,
		// 				Type:         credential.Descriptor().Type,
		// 			},
		// 		}),
		// 	)
		// }
	}

	options, session, err := restService.webAuthn.BeginRegistration(user, opts...)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	err = restService.registrationService.Create(&entities.Registration{
		ID:          userID,
		Email:       user.Email,
		SessionData: sessionJSON,
	})
	if err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	restService.responseWriter.Write(w, r, http.StatusOK, options)
}

func (restService *WebAuthnRestService) FinishRegistration(w http.ResponseWriter, r *http.Request) {

	restService.logger.Debug("webauthn finish registration")

	xuserID := r.Header.Get("X-User-Id")
	if xuserID == "" {
		restService.responseWriter.Error400(w, r, ErrInvalidUserIDHeader)
		return
	}

	sUserID, err := base64.RawURLEncoding.DecodeString(xuserID)
	if xuserID == "" {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	userID, err := strconv.ParseUint(string(sUserID), 10, 64)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	registration, err := restService.registrationService.Get(service.NewSession(), userID)
	if err != nil {
		restService.responseWriter.Error404(w, r, err)
		return
	}
	user := &entities.User{
		ID:          userID,
		Email:       registration.Email,
		SessionData: registration.SessionData,
	}

	var sessionData webauthn.SessionData
	err = json.Unmarshal(user.SessionData, &sessionData)
	if err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	credential, err := restService.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	existingUser, err := restService.userService.Get(userID)
	if err != nil {
		if err != datastore.ErrRecordNotFound {
			restService.responseWriter.Error500(w, r, err)
			return
		}
	} else {
		user = existingUser
	}

	user.AddCredential(credential)
	if err := restService.userService.Save(user); err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	if err := restService.registrationService.Delete(service.NewSession(), userID); err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	tokenString, err := restService.jwtService.GenerateToken(user)
	if err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	restService.responseWriter.Success200(w, r, tokenString)
}

func (restService *WebAuthnRestService) BeginLogin(w http.ResponseWriter, r *http.Request) {

	restService.logger.Debug("webauthn begin login")

	userID, err := getUserID(r)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	user, err := restService.userService.Get(userID)
	if err != nil {
		if err == datastore.ErrRecordNotFound {
			restService.responseWriter.Error400(w, r, ErrInvalidUserID)
			return
		}
		restService.responseWriter.Error400(w, r, err)
		return
	}

	options, session, err := restService.webAuthn.BeginLogin(user)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	sessionDataBytes, err := json.Marshal(session)
	if err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	user.SessionData = sessionDataBytes

	if err := restService.userService.Save(user); err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	w.Header().Set("Access-Control-Expose-Headers", "X-User-ID")
	w.Header().Set("X-User-ID", fmt.Sprintf("%d", userID))

	restService.responseWriter.Write(w, r, http.StatusOK, options)
}

func (restService *WebAuthnRestService) FinishLogin(w http.ResponseWriter, r *http.Request) {

	restService.logger.Debug("webauthn finish login")

	userID, err := getUserID(r)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	user, err := restService.userService.Get(userID)
	if err != nil {
		restService.responseWriter.Error404(w, r, err)
		return
	}

	var sessionData webauthn.SessionData
	err = json.Unmarshal(user.SessionData, &sessionData)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	credential, err := restService.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	if credential.Authenticator.CloneWarning {
		restService.logger.Warn("rest/webauthn: credential.Authenticator.CloneWarning")
	}

	user.UpdateCredential(credential)

	if err := restService.userService.Save(user); err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	tokenString, err := restService.jwtService.GenerateToken(user)
	if err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	restService.responseWriter.Success200(w, r, tokenString)
}

func (restService *WebAuthnRestService) Verify(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	userID, err := getUserID(r)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	user, err := restService.userService.Get(userID)
	if err != nil {
		restService.responseWriter.Error404(w, r, err)
		return
	}

	var sessionData webauthn.SessionData
	err = json.Unmarshal(user.SessionData, &sessionData)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	if sessionData.Expires.Before(time.Now()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	next.ServeHTTP(w, r)
}

func (restService *WebAuthnRestService) RegistrationStatus(w http.ResponseWriter, r *http.Request) {

	userID, err := getUserID(r)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	if userID == 0 {
		restService.responseWriter.Write(w, r, http.StatusOK, "not_registered")
		return
	}

	user, err := restService.userService.Get(userID)
	if err != nil {
		restService.responseWriter.Write(w, r, http.StatusOK, "not_registered")
		return
	}

	var sessionData webauthn.SessionData
	err = json.Unmarshal(user.SessionData, &sessionData)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	if sessionData.Expires.Before(time.Now()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	restService.responseWriter.Write(w, r, http.StatusOK, "registered")
}

func getUserID(r *http.Request) (uint64, error) {

	xuserID := r.Header.Get("X-User-Id")
	if xuserID == "" {
		var u request
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			return 0, ErrInvalidUserIDHeader
		}
		return util.NewID([]byte(u.Email)), nil
	}

	// var userID uint64
	userID, err := strconv.ParseUint(string(xuserID), 10, 64)
	if err != nil {
		if err == strconv.ErrSyntax {
			userID = util.NewID([]byte(xuserID))
		} else {
			return 0, err
		}
	}

	return userID, nil
}
