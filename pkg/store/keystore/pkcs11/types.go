package pkcs11

import "errors"

var (
	ErrUnsupportedKeyAlgorithm = errors.New("keystore/pkcs11: unsupported key algorithm")
	ErrUnsupportedOperation    = errors.New("keystore/pkcs11: unsupported operation")
	ErrInvalidSOPIN            = errors.New("keystore/pkcs11: invalid security officer pin")
	ErrInvalidUserPIN          = errors.New("keystore/pkcs11: invalid user pin")
	ErrInvalidTokenLabel       = errors.New("keystore/pkcs11: invalid token label")
	ErrInvalidPINLength        = errors.New("keystore/pkcs11: invalid pin length, must be at least 4 characters")
)
