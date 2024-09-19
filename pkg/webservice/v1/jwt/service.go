package jwt

import (
	"crypto"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type JsonWebTokenClaims struct {
	Email         string   `json:"email"`
	Organizations []uint64 `json:"orgs"`
	Services      []uint64 `json:"svcs"`
	UserID        uint64   `json:"uid"`
	jwt.RegisteredClaims
}

type Service struct {
	config        *config.WebService
	signer        crypto.Signer
	signingMethod jwt.SigningMethod
}

func NewService(config *config.WebService,
	keyring *platform.Keyring,
	keyAttrs *keystore.KeyAttributes) (*Service, error) {

	signingMethod, err := NewSigningMethod(keyAttrs)
	if err != nil {
		return nil, err
	}
	signer, err := keyring.Signer(keyAttrs)
	if err != nil {
		return nil, err
	}
	return &Service{
		config:        config,
		signer:        signer,
		signingMethod: signingMethod,
	}, nil
}

func (service *Service) GenerateToken(user *entities.User) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(service.signingMethod, JsonWebTokenClaims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{service.config.Certificate.Subject.CommonName},
			Issuer:   service.config.JWT.Issuer,
			IssuedAt: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(
				now.Add(time.Minute * time.Duration(service.config.JWT.Expiration))),
			NotBefore: jwt.NewNumericDate(now),
		},
	})
	return token.SignedString(service.signer)
}

func (service *Service) ParseToken(tokenString string) (*jwt.Token, error) {
	parser := jwt.NewParser()
	claims := &JsonWebTokenClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, service.KeyFunc)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (service *Service) KeyFunc(token *jwt.Token) (interface{}, error) {
	return service.signer.Public(), nil
}

func (service *Service) PublicKey() crypto.PublicKey {
	return service.signer.Public()
}
