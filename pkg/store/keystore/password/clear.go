package password

import "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"

type ClearPassword struct {
	password []byte
	keystore.Password
}

// Stores a clear text password
func NewClearPassword(password []byte) keystore.Password {
	return ClearPassword{password: password}
}

func NewClearPasswordFromString(password string) keystore.Password {
	return ClearPassword{password: []byte(password)}
}

// Returns the password as a string
func (p ClearPassword) String() (string, error) {
	return string(p.password), nil
}

// Returns the password as bytes
func (p ClearPassword) Bytes() ([]byte, error) {
	return p.password, nil
}
