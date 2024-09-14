package rest

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/op/go-logging"
)

// https://gist.github.com/soulmachine/b368ce7292ddd7f91c15accccc02b8df

type JsonWebTokenServicer interface {
	ParseToken(r *http.Request, extractor request.Extractor) (*jwt.Token, *JsonWebTokenClaims, error)
	middleware.AuthMiddleware
	middleware.JsonWebTokenMiddleware
}

type JWTService struct {
	claimsIssuer   string
	expiration     time.Duration
	responseWriter response.HttpWriter
	publicKey      *rsa.PublicKey
	JsonWebTokenServicer
	logger *logging.Logger
	middleware.JsonWebTokenMiddleware
	signer crypto.Signer
}

type JsonWebTokenClaims struct {
	ServerID uint64 `json:"sid"`
	UserID   uint64 `json:"uid"`
	Email    string `json:"email"`
	Services string `json:"services"`
	jwt.StandardClaims
}

type JsonWebToken struct {
	Value string `json:"token"`
	Error string `json:"error"`
}

// Instantiate a new JsonWebTokenService
func NewJsonWebTokenService(
	responseWriter response.HttpWriter,
	expiration int,
	signer crypto.Signer,
	claimsIssuer string) (JsonWebTokenServicer, error) {

	return &JWTService{
		claimsIssuer:   claimsIssuer,
		responseWriter: responseWriter,
		expiration:     time.Duration(expiration),
		logger:         util.Logger(),
		signer:         signer}, nil
}

// Creates a new web service session by parsing the organization and Service from
// the JWT Claims and creating a service.Session object that represents the
// user and their organization and Service membership.
func (jwtService *JWTService) CreateSession(w http.ResponseWriter,
	r *http.Request) (service.Session, error) {

	jwtService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	_, claims, err := jwtService.parseToken(w, r)
	if err != nil {
		return nil, err
	}
	jwtService.logger.Debugf("Claims: %+v", claims)

	serviceClaims, err := jwtService.parseServiceClaims(claims.Services)
	if err != nil {
		return nil, err
	}

	return service.CreateSession(
		jwtService.logger,
		serviceClaims,
		serviceClaims[0].ID), nil
}

func (jwtService *JWTService) GenerateToken(w http.ResponseWriter, req *http.Request) {

	jwtService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		req.URL.Path, req.Method, req.RemoteAddr, req.RequestURI)

	var user service.UserCredentials
	err := json.NewDecoder(req.Body).Decode(&user)
	// jwtService.logger.Debugf("Decoded userCredentials: %v+", user)
	if err != nil {
		jwtService.responseWriter.Error400(w, req, err)
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, JsonWebTokenClaims{
		ServerID: uint64(1),
		UserID:   1,
		Email:    "root@example.com",
		//Services: string(serviceClaimsJson),
		StandardClaims: jwt.StandardClaims{
			Issuer:    jwtService.claimsIssuer,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Minute * jwtService.expiration).Unix()}})

	tokenString, err := token.SignedString(jwtService.signer)
	if err != nil {
		jwtService.responseWriter.Write(w, req,
			http.StatusInternalServerError, JsonWebToken{Error: "Error signing token"})
		return
	}

	jwtService.logger.Debugf("Generated JSON token: %s", tokenString)

	jwtViewModel := JsonWebToken{Value: tokenString}
	jwtService.responseWriter.Write(w, req, http.StatusOK, jwtViewModel)
}

func (jwtService *JWTService) RefreshToken(w http.ResponseWriter, req *http.Request) {

	jwtService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		req.URL.Path, req.Method, req.RemoteAddr, req.RequestURI)

	token, claims, err := jwtService.parseToken(w, req)
	if err == nil {
		if token.Valid {

			jwtService.logger.Debugf("claims: %+v", claims)

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

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, JsonWebTokenClaims{
				ServerID: uint64(1),
				UserID:   1,
				Email:    "root@example.com",
				//Services: string(serviceClaimsJson),
				StandardClaims: jwt.StandardClaims{
					Issuer:    jwtService.claimsIssuer,
					IssuedAt:  time.Now().Unix(),
					ExpiresAt: time.Now().Add(time.Minute * jwtService.expiration).Unix()}})

			tokenString, err := token.SignedString(jwtService.signer)
			if err != nil {
				jwtService.responseWriter.Write(w, req, http.StatusInternalServerError,
					JsonWebToken{Error: "Error signing token"})
				return
			}

			jwtService.logger.Debugf("Refreshed JSON token: %s", tokenString)

			tokenDTO := JsonWebToken{Value: tokenString}
			jwtService.responseWriter.Write(w, req, http.StatusOK, tokenDTO)

		} else {
			jwtService.logger.Errorf("Invalid token: %s", token.Raw)
			jwtService.responseWriter.Write(w, req, http.StatusUnauthorized,
				JsonWebToken{Error: "Invalid token"})
		}
	} else {
		errmsg := err.Error()
		if errmsg == "no token present in request" {
			errmsg = "Authentication required"
		}
		jwtService.logger.Errorf("Error: %s", errmsg)
		http.Error(w, errmsg, http.StatusBadRequest)
	}
}

// Validates the raw JWT token to ensure it's not expired or contains any invalid claims. This
// is used by the negroni middleware to enforce authenticated access to procted resources.
func (jwtService *JWTService) Validate(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	jwtService.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, claims, err := jwtService.parseToken(w, r)
	if err == nil {
		if token.Valid {
			if claims.UserID <= 0 {
				errmsg := "Invalid request. id claim required."
				jwtService.logger.Errorf("%s", errmsg)
				jwtService.logger.Errorf("token: %+v", token.Raw)
				http.Error(w, errmsg, http.StatusBadRequest)
				return
			}
			if claims.Email == "" {
				errmsg := "Invalid request. email claim required"
				jwtService.logger.Errorf("%s", errmsg)
				jwtService.logger.Errorf("token: %+v", token.Raw)
				http.Error(w, errmsg, http.StatusBadRequest)
				return
			}
			next(w, r)
		} else {
			jwtService.logger.Errorf("invalid token: %s", token.Raw)
			http.Error(w, "invalid token", http.StatusUnauthorized)
		}
	} else {
		errmsg := err.Error()
		if errmsg == "no token present in request" {
			errmsg = "Authentication required"
		}
		jwtService.logger.Errorf("Error: %s", errmsg)
		http.Error(w, errmsg, http.StatusBadRequest)
	}
}

// Used to determine if the specified organization is a member of any of the specified OrganizationClaims
func (jwtService *JWTService) isOrgMember(serviceClaims []service.ServiceClaim, serviceID uint64) bool {
	for _, service := range serviceClaims {
		if service.ID == serviceID {
			return true
		}
	}
	return false
}

// Parses a list of OrganizationClaims from a json string
func (jwtService *JWTService) parseServiceClaims(ServiceJson string) ([]service.ServiceClaim, error) {
	var serviceClaims []service.ServiceClaim
	reader := strings.NewReader(ServiceJson)
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&serviceClaims); err != nil {
		jwtService.logger.Errorf("parseServiceClaims error: %s", err)
		return []service.ServiceClaim{}, err
	}
	return serviceClaims, nil
}

// Parses the JsonWebTokenClaims from the HTTP request
func (jwtService *JWTService) parseClaims(r *http.Request, extractor request.Extractor) (*jwt.Token, *JsonWebTokenClaims, error) {
	token, err := request.ParseFromRequest(r, extractor,
		func(token *jwt.Token) (interface{}, error) {
			return jwtService.publicKey, nil
		})
	if err != nil {
		return nil, nil, err
	}
	claims := &JsonWebTokenClaims{}
	_, err = jwt.ParseWithClaims(token.Raw, claims,
		func(token *jwt.Token) (interface{}, error) {
			return jwtService.publicKey, nil
		})
	if err != nil {
		return nil, nil, err
	}
	jwtService.logger.Debugf("claims: %+v", claims)
	return token, claims, nil
}

// Parses the JsonWebTokenClaims from the HTTP request using either an OAuth2 or
// Authorization header based on their presence in the HTTP request.
func (jwtService *JWTService) parseToken(w http.ResponseWriter, r *http.Request) (*jwt.Token, *JsonWebTokenClaims, error) {
	var token *jwt.Token
	var claims *JsonWebTokenClaims
	var err error
	if _, ok := r.URL.Query()["access_token"]; ok {
		t, c, e := jwtService.parseClaims(r, request.OAuth2Extractor)
		token = t
		claims = c
		err = e
	} else {
		t, c, e := jwtService.parseClaims(r, request.AuthorizationHeaderExtractor)
		token = t
		claims = c
		err = e
	}
	if err != nil {
		errmsg := err.Error()
		jwtService.logger.Errorf("parseToken error: %s", errmsg)
		return nil, nil, errors.New(errmsg)
	}
	jwtService.logger.Debugf("token=%+v", token)
	return token, claims, err
}
