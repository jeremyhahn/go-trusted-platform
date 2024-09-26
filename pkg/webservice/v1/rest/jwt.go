package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

var (
	ErrInvalidOrganiztionID = errors.New("rest/jwt: invalid organization id")
)

type JsonWebTokenServicer interface {
	middleware.JsonWebTokenMiddleware
}

type JsonWebTokenRestService struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	jwtService     *jwt.Service
	userService    service.UserServicer
	JsonWebTokenServicer
}

// Instantiate a new JsonWebTokenService
func NewJsonWebTokenRestService(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	jwtService *jwt.Service,
	userService service.UserServicer) (JsonWebTokenServicer, error) {

	return &JsonWebTokenRestService{
		logger:         logger,
		responseWriter: responseWriter,
		jwtService:     jwtService}, nil
}

// Creates a new web service session from the parsed JWT
func (restService *JsonWebTokenRestService) CreateSession(
	w http.ResponseWriter,
	r *http.Request) (service.Session, error) {

	restService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	_, claims, err := restService.jwtService.ParseToken(w, r)
	if err != nil {
		return nil, err
	}

	restService.logger.Debugf("rest/jwt: claims: %+v", claims)

	var requestedOrgID, requestedServiceID uint64

	params := mux.Vars(r)
	orgIDParam := params["organization_id"]
	serviceIDParam := params["service_id"]

	if orgIDParam != "" {
		requestedOrgID, err = strconv.ParseUint(orgIDParam, 10, 64)
		if err != nil {
			return nil, ErrInvalidOrganiztionID
		}
	}
	if serviceIDParam != "" {
		// ignore errors here; may be a new system without any services
		// configured
		requestedServiceID, _ = strconv.ParseUint(serviceIDParam, 10, 64)
	}

	user, err := restService.userService.Get(claims.UserID)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return nil, err
	}

	return service.CreateSession(
		restService.logger,
		claims.Organizations,
		requestedOrgID,
		requestedServiceID,
		claims.Services,
		user), nil
}

// Decodes the requst body to a service.UserCredentials structure and generates a new
// JWT using the unmarshalled username and password.
func (restService *JsonWebTokenRestService) GenerateToken(w http.ResponseWriter, req *http.Request) {

	restService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		req.URL.Path, req.Method, req.RemoteAddr, req.RequestURI)

	var userCred service.UserCredential
	if err := json.NewDecoder(req.Body).Decode(&userCred); err != nil {
		restService.responseWriter.Error400(w, req, err)
		return
	}

	// userService := jwtService.serviceRegistry.GetUserService()
	// userAccount, orgs, Services, err := userService.Login(&user)
	// if err != nil {
	// 	jwtService.logger.Errorf("GenerateToken login error: %s", err)
	// 	jwtService.responseWriter.Write(w, req, http.StatusForbidden,
	// 		JsonWebToken{Error: "Invalid credentials"})
	// 	return
	// }

	// if len(userAccount.GetRoles()) == 0 {
	// 	// Must be a new user that hasn't been assigned to any roles yet
	// 	userAccount.SetRoles([]model.Role{
	// 		&model.RoleStruct{
	// 			ID:   jwtService.defaultRole.ID,
	// 			Name: jwtService.defaultRole.Name}})
	// }

	// jwtService.logger.Debugf("user: %+v", user)
	// jwtService.logger.Debugf("userAccount: %+v", userAccount)
	// jwtService.logger.Debugf("orgs: %+v", orgs)
	// jwtService.logger.Debugf("org.len: %+v", len(orgs))
	// jwtService.logger.Debugf("Services.len: %+v", len(Services))

	// roleClaims := make([]string, len(userAccount.GetRoles()))
	// for j, role := range userAccount.GetRoles() {
	// 	roleClaims[j] = role.GetName()
	// }

	// orgClaims := make([]service.OrganizationClaim, len(orgs))
	// for i, org := range orgs {
	// 	ServiceClaims := make([]service.ServiceClaim, len(org.GetServices()))
	// 	for j, Service := range org.GetServices() {
	// 		ServiceClaims[j] = service.ServiceClaim{
	// 			ID:   Service.ID,
	// 			Name: Service.GetName()}
	// 		// Not sending roles here to keep JWT compact; imposes
	// 		// logic to default Service roles to org roles on the client
	// 		//Roles: roleClaims}
	// 	}
	// 	orgClaims[i] = service.OrganizationClaim{
	// 		ID:       org.Identifier(),
	// 		Name:     org.GetName(),
	// 		Services: ServiceClaims,
	// 		Roles:    roleClaims}
	// }

	// serviceClaims := make([]service.ServiceClaim, len(Services))
	// for i, Service := range serviceClaims {
	// 	serviceClaims[i] = service.ServiceClaim{
	// 		ID:   Service.Identifier(),
	// 		Name: Service.GetName()}
	// }
	// serviceClaimsJson, err := json.Marshal(serviceClaims)
	// if err != nil {
	// 	jwtService.responseWriter.Write(w, req, http.StatusInternalServerError,
	// 		JsonWebToken{Error: "Error marshaling Services"})
	// 	return
	// }

	user := entities.NewUser(userCred.Email)

	tokenString, err := restService.jwtService.GenerateToken(user)
	if err != nil {
		restService.responseWriter.Error500(w, req, err)
		return
	}

	restService.logger.Debugf("rest/jwt: generated token: %s", tokenString)

	restService.responseWriter.Success200(w, req, tokenString)
}

// Exchange a JWT for a new token with a new expiration date
func (restService *JsonWebTokenRestService) RefreshToken(w http.ResponseWriter, r *http.Request) {

	restService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, claims, err := restService.jwtService.ParseToken(w, r)
	if err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	if !token.Valid {
		restService.responseWriter.Error401(w, r, ErrInvalidToken)
		return
	}

	restService.logger.Debugf("rest/jwt: claims: %+v", claims)

	// userService := jwtService.serviceRegistry.GetUserService()
	// userAccount, services, err := userService.Refresh(claims.UserID)
	// if err != nil {
	// 	jwtService.logger.Errorf("Error refreshing token: %s", err)
	// 	jwtService.responseWriter.Write(w, req, http.StatusUnauthorized,
	// 		JsonWebToken{Error: "Invalid token"})
	// 	return
	// }

	// serviceClaims := make([]service.ServiceClaim, len(services))
	// for i, Service := range services {
	// 	roles := make([]string, 0)
	// 	for _, user := range Service.GetUsers() {
	// 		if user.ID == userAccount.Identifier() {
	// 			for _, role := range user.GetRoles() {
	// 				roles = append(roles, role.GetName())
	// 			}
	// 		}
	// 	}
	// 	serviceClaims[i] = service.ServiceClaim{
	// 		ID:    Service.Identifier(),
	// 		Name:  Service.GetName()}
	// }
	// serviceClaimsJson, err := json.Marshal(serviceClaims)
	// if err != nil {
	// 	jwtService.responseWriter.Write(w, req, http.StatusInternalServerError,
	// 		JsonWebToken{Error: "Error marshaling Services"})
	// 	return
	// }

	user := &entities.User{
		ID: claims.UserID,
	}

	tokenString, err := restService.jwtService.GenerateToken(user)
	if err != nil {
		restService.responseWriter.Error500(w, r, err)
		return
	}

	restService.logger.Debugf("rest/jwt: refreshed token: %s", tokenString)

	restService.responseWriter.Success200(w, r, tokenString)
}

// Validates the raw JWT token to ensure it's not expired or contains invalid claims. This
// is used by the negroni middleware to enforce authenticated access to procted resources.
func (restService *JsonWebTokenRestService) Verify(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	restService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, _, err := restService.jwtService.ParseToken(w, r)
	if err != nil {
		// Error response already sent
		return
	}

	if err := restService.jwtService.Verify(token); err != nil {
		restService.responseWriter.Error400(w, r, err)
		return
	}

	next(w, r)
}
