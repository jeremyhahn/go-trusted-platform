package rest

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

type InMem struct {
	// TODO: it would be nice to have a mutex here
	// TODO: use pointers to avoid copying
	users    map[string]*entities.User
	sessions map[string]webauthn.SessionData

	log Logger
}

type Logger interface {
	Printf(format string, v ...interface{})
}

func (i *InMem) GenSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil

}

func NewInMem(log Logger) *InMem {
	return &InMem{
		users:    make(map[string]*entities.User),
		sessions: make(map[string]webauthn.SessionData),
		log:      log,
	}
}

func (i *InMem) GetSession(token string) (webauthn.SessionData, bool) {
	i.log.Printf("[DEBUG] GetSession: %v", i.sessions[token])
	val, ok := i.sessions[token]

	return val, ok
}

func (i *InMem) SaveSession(token string, data webauthn.SessionData) {
	i.log.Printf("[DEBUG] SaveSession: %s - %v", token, data)
	i.sessions[token] = data
}

func (i *InMem) DeleteSession(token string) {
	i.log.Printf("[DEBUG] DeleteSession: %v", token)
	delete(i.sessions, token)
}

func (i *InMem) GetOrCreateUser(userName string) *entities.User {
	i.log.Printf("[DEBUG] GetOrCreateUser: %v", userName)
	if _, ok := i.users[userName]; !ok {
		i.log.Printf("[DEBUG] GetOrCreateUser: creating new user: %v", userName)
		i.users[userName] = &entities.User{
			ID:          util.NewID([]byte(userName)),
			DisplayName: userName,
			Email:       userName,
		}
	}

	return i.users[userName]
}

func (i *InMem) SaveUser(user *entities.User) {
	i.log.Printf("[DEBUG] SaveUser: %v", user.WebAuthnName())
	i.log.Printf("[DEBUG] SaveUser: %v", user)
	i.users[user.WebAuthnName()] = user
}
