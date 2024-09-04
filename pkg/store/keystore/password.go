package keystore

// A secret is a private piece of information that unlocks
// protected data or resources, and can include passwords,
// but also other types of sensitive data. Passwords can be
// used for a variety of purposes, including system-to-system
// interactions, such as when a web application communicates
// with a database.

// Passwords are a type of secret that are often used to access
// computer systems or enter a place, such as a protected vault.
type Password interface {
	String() (string, error)
	Bytes() ([]byte, error)
}

type ClearPassword struct {
	password []byte
	Password
}

// Creates a new clear text password stored in memory
func NewClearPassword(password []byte) Password {
	return ClearPassword{password: password}
}

// Creates a new clear text password stored in memory from a string
func NewClearPasswordFromString(password string) Password {
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
