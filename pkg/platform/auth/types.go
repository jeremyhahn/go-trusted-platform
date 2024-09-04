package auth

import "errors"

var (
	ErrAuthenticationFailed = errors.New("platform: authentication failed")
)

type PlatformAuthenticator interface {
	Authenticate(password []byte) error
	Prompt() []byte
	Provision(cn string, password, caPassword []byte) error
}
