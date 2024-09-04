package password

import "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"

type RequiredPassword struct {
	keystore.Password
}

// Creates a secret that always returns ErrPasswordRequired
func NewRequiredPassword() keystore.Password {
	return RequiredPassword{}
}

// Returns ErrPasswordRequired
func (p RequiredPassword) String() (string, error) {
	return "", keystore.ErrPasswordRequired
}

// Returns ErrPasswordRequired
func (p RequiredPassword) Bytes() ([]byte, error) {
	return nil, keystore.ErrPasswordRequired
}
