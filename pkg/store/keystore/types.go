package keystore

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/op/go-logging"
)

type RSAScheme string
type Curve string
type StoreType string

const (
	// String literals using in platform configuration file
	STORE_PKCS8  StoreType = "PKCS8"
	STORE_PKCS11 StoreType = "PKCS11"

	RSA_SCHEME_RSAPSS   RSAScheme = "RSA_PSS"
	RSA_SCHEME_PKCS1v15 RSAScheme = "PKCS1v15"

	CURVE_P224 Curve = "P256"
	CURVE_P256 Curve = "P256"
	CURVE_P384 Curve = "P386"
	CURVE_P521 Curve = "P521"

	// Internal types not stored in the platform configuration file
	KEY_TYPE_CA KeyType = 1 + iota
	KEY_TYPE_TLS
	KEY_TYPE_SIGNING
	KEY_TYPE_ENCRYPTION
	KEY_TYPE_NULL

	X509_TYPE_TRUSTED_ROOT X509Type = 1 + iota
	X509_TYPE_TRUSTED_INTERMEDIATE
	X509_TYPE_TLS
	X509_TYPE_LOCAL_ATTESTATION
	X509_TYPE_REMOTE_ATTESTATION

	ENCRYPT_ALGORITHM_RSA_PKCS1v15 = 1 + iota
	ENCRYPT_ALGORITHM_RSA_OAEP
	ENCRYPT_ALGORITHM_ECDH

	WRAP_ALGORITHM_AES_GCM WrapAlgorithm = 1 + iota
	WRAP_ALGORITHM_AES_CFB
)

var (
	ErrInvalidKeyType            = errors.New("store/keystore: invalid key type")
	ErrInvalidKeyAlgorithm       = errors.New("store/keystore: invalid key algorithm")
	ErrInvalidPrivateKey         = errors.New("store/keystore: invalid private key")
	ErrInvalidPrivateKeyRSA      = errors.New("store/keystore: invalid RSA private key")
	ErrInvalidPrivateKeyECDSA    = errors.New("store/keystore: invalid ECDSA private key")
	ErrInvalidPrivateKeyEd25519  = errors.New("store/keystore: invalid Ed25519 private key")
	ErrInvalidOpaquePrivateKey   = errors.New("store/keystore: invalid opaque private key")
	ErrInvalidSignerOpts         = errors.New("store/keystore: invalid signer opts, password required")
	ErrInvalidKeyStore           = errors.New("store/keystore: invalid key store")
	ErrInvalidSignatureAlgorithm = errors.New("store/keystore: unsupported signing algorithm")
	ErrInvalidSignatureScheme    = errors.New("store/keystore: invalid signature scheme")
	ErrKeyAlreadyExists          = errors.New("store/keystore: key already exists")
	ErrFileIntegrityCheckFailed  = errors.New("store/keystore: file integrity check failed")
	ErrInvalidPublicKeyRSA       = errors.New("store/keystore: invalid RSA public key")
	ErrInvalidPublicKeyECDSA     = errors.New("store/keystore: invalid ECDSA public key")
	ErrSingatureVerification     = errors.New("store/keystore: signature verification failed")
	ErrInvalidCurve              = errors.New("store/keystore: invalid ECC curve")
	ErrInvalidHashFunction       = errors.New("store/keystore: invalid hash function")
	ErrInvalidKeyAttributes      = errors.New("store/keystore: invalid key attributes")
	ErrInvalidBlobName           = errors.New("store/keystore: invalid blob name")
	ErrDomainAttributeRequired   = errors.New("store/keystore: domain key attribute required")
)

type KeyStorer interface {
	CreateKey(attrs KeyAttributes) (OpaqueKey, error)
	CreateRSA(attrs KeyAttributes) (OpaqueKey, error)
	CreateECDSA(attrs KeyAttributes) (OpaqueKey, error)
	CreateEd25519(attrs KeyAttributes) (OpaqueKey, error)
	Decrypter(attrs KeyAttributes) (crypto.Decrypter, error)
	Equal(opaque Opaque, x crypto.PrivateKey) bool
	Key(attrs KeyAttributes) (crypto.Signer, error)
	Signer(attrs KeyAttributes) (crypto.Signer, error)
	Type() StoreType
	Verifier(attrs KeyAttributes, opts *VerifyOpts) Verifier
}

type Verifier interface {
	Verify(
		pub crypto.PublicKey,
		hash crypto.Hash,
		hashed, signature []byte,
		opts *VerifyOpts) error
}

type VerifyOpts struct {
	KeyAttributes  KeyAttributes
	BlobCN         string
	IntegrityCheck bool
	PSSOptions     *rsa.PSSOptions
}

type KeyAttributes struct {
	DebugSecrets       bool
	AuthPassword       []byte
	ECCAttributes      *ECCAttributes
	RSAAttributes      *RSAAttributes
	Domain             string
	CN                 string
	Hash               crypto.Hash
	KeyAlgorithm       x509.PublicKeyAlgorithm
	KeyType            KeyType
	Password           []byte
	SignatureAlgorithm x509.SignatureAlgorithm
	Wrap               bool
	WrapAlgorithm      *WrapAlgorithm
	WrapPassword       []byte
	X509Attributes     *X509Attributes

	// KeyName            string
}

type X509Attributes struct {
	CN   string
	Type X509Type
	// KeyAlgorithm x509.PublicKeyAlgorithm
}

type ECCAttributes struct {
	KeyAttributes
	Curve elliptic.Curve
}

type RSAAttributes struct {
	KeyAttributes
	KeySize   int
	KeyScheme RSAScheme
}

type EncryptionAlgorithm uint8

func (algo EncryptionAlgorithm) String() string {
	switch algo {
	case ENCRYPT_ALGORITHM_RSA_PKCS1v15:
		return "RSA_PKCS1v15"
	case ENCRYPT_ALGORITHM_RSA_OAEP:
		return "RSA_OAEP"
	case ENCRYPT_ALGORITHM_ECDH:
		return "ECDH"
	}
	panic("store/keystore: invalid encryption algorithm")
}

type KeyType uint8

func (keyType KeyType) String() string {
	switch keyType {
	case KEY_TYPE_CA:
		return "CA"
	case KEY_TYPE_TLS:
		return "TLS"
	case KEY_TYPE_SIGNING:
		return "SIGN"
	case KEY_TYPE_ENCRYPTION:
		return "ENCRYPT"
	}
	panic("store/keystore: invalid key type attribute")
}

type X509Type uint8

func (x509Type X509Type) String() string {
	switch x509Type {
	case X509_TYPE_TRUSTED_ROOT:
		return "Trusted Root"
	case X509_TYPE_TRUSTED_INTERMEDIATE:
		return "Trusted Intermediate"
	case X509_TYPE_TLS:
		return "TLS"
	}
	panic("store/keystore: invalid x509 certificate type attribute")
}

type WrapAlgorithm uint8

func (algo WrapAlgorithm) String() string {
	switch algo {
	case WRAP_ALGORITHM_AES_GCM:
		return "AES_GCM"
	case WRAP_ALGORITHM_AES_CFB:
		return "AES_CFB"
	}
	panic("store/keystore: invalid wrap algorithm")
}

func DebugKeyAttributes(logger *logging.Logger, attrs KeyAttributes) {

	logger.Debug("Key Attributes")
	logger.Debugf("  Hash: %s", attrs.Hash.String())
	logger.Debugf("  Key Algorithm: %s", attrs.KeyAlgorithm)
	logger.Debugf("  Signature Algorithm: %s", attrs.SignatureAlgorithm.String())
	logger.Debugf("  Domain: %s", attrs.Domain)
	logger.Debugf("  Common Name: %s", attrs.CN)
	logger.Debugf("  Type: %s", attrs.KeyType)
	logger.Debugf("  Wrap: %t", attrs.Wrap)
	if attrs.WrapAlgorithm != nil {
		logger.Debugf("  Wrap Algorithm: %s", attrs.WrapAlgorithm.String())
	}

	if attrs.ECCAttributes != nil {
		logger.Debug("ECC Attributes")
		logger.Debugf("  Curve: %+v", attrs.ECCAttributes.Curve)
	} else if attrs.RSAAttributes != nil {
		logger.Debug("RSA Attributes")
		logger.Debugf("  Size: %d", attrs.RSAAttributes.KeySize)
		// logger.Debugf("  Scheme: %+v", attrs.RSAAttributes.KeyScheme)
	}

	if attrs.X509Attributes != nil {
		logger.Debug("X509 Attributes")
		logger.Debugf("  Common Name: %s", attrs.X509Attributes.CN)
		logger.Debugf("  Type %s", attrs.X509Attributes.Type.String())
	}

	if attrs.DebugSecrets {
		logger.Debug("Key Passwords")
		logger.Debugf("  Key Password: %s", attrs.Password)
		logger.Debugf("  Wrap Password:  %s", attrs.WrapPassword)
	}
}

// Creates a new digest using the specified hash function
func Digest(hash crypto.Hash, data []byte) ([]byte, error) {
	hasher := hash.New()
	hasher.Reset()
	n, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, common.ErrCorruptWrite
	}
	digest := hasher.Sum(nil)
	return digest[:], err
}

func AvailableHashes() map[string]crypto.Hash {
	hashes := make(map[string]crypto.Hash)
	hashes[crypto.MD4.String()] = crypto.MD4
	hashes[crypto.MD5.String()] = crypto.MD5
	hashes[crypto.SHA1.String()] = crypto.SHA1
	hashes[crypto.SHA224.String()] = crypto.SHA224
	hashes[crypto.SHA256.String()] = crypto.SHA256
	hashes[crypto.SHA384.String()] = crypto.SHA384
	hashes[crypto.SHA512.String()] = crypto.SHA512
	hashes[crypto.MD5SHA1.String()] = crypto.MD5SHA1
	hashes[crypto.RIPEMD160.String()] = crypto.RIPEMD160
	hashes[crypto.SHA3_224.String()] = crypto.SHA3_224
	hashes[crypto.SHA3_256.String()] = crypto.SHA3_256
	hashes[crypto.SHA3_384.String()] = crypto.SHA3_384
	hashes[crypto.SHA3_512.String()] = crypto.SHA3_512
	hashes[crypto.SHA512_224.String()] = crypto.SHA512_224
	hashes[crypto.SHA512_256.String()] = crypto.SHA512_256
	hashes[crypto.BLAKE2s_256.String()] = crypto.BLAKE2s_256
	hashes[crypto.BLAKE2b_256.String()] = crypto.BLAKE2b_256
	hashes[crypto.BLAKE2b_384.String()] = crypto.BLAKE2b_384
	hashes[crypto.BLAKE2b_512.String()] = crypto.BLAKE2b_512
	return hashes
}

func DebugAvailableHashes(logger *logging.Logger) {
	hashes := AvailableHashes()
	logger.Debug("Available Hash Functions")
	for _, v := range hashes {
		logger.Debugf("  %s", v)
	}
}

func AvailableSignatureAlgorithms() map[string]x509.SignatureAlgorithm {
	algos := make(map[string]x509.SignatureAlgorithm)
	algos[x509.SHA256WithRSA.String()] = x509.SHA256WithRSA
	algos[x509.SHA384WithRSA.String()] = x509.SHA384WithRSA
	algos[x509.SHA512WithRSA.String()] = x509.SHA512WithRSA
	algos[x509.ECDSAWithSHA256.String()] = x509.ECDSAWithSHA256
	algos[x509.ECDSAWithSHA384.String()] = x509.ECDSAWithSHA384
	algos[x509.ECDSAWithSHA512.String()] = x509.ECDSAWithSHA512
	algos[x509.SHA256WithRSAPSS.String()] = x509.SHA256WithRSAPSS
	algos[x509.SHA384WithRSAPSS.String()] = x509.SHA384WithRSAPSS
	algos[x509.SHA512WithRSAPSS.String()] = x509.SHA512WithRSAPSS
	algos[x509.PureEd25519.String()] = x509.PureEd25519
	return algos
}

func DebugAvailableSignatureAkgorithms(logger *logging.Logger) {
	algos := AvailableSignatureAlgorithms()
	logger.Debug("Available Signature Algorithms")
	for _, v := range algos {
		logger.Debugf("  %s", v)
	}
}

func AvailableKeyAlgorithms() map[string]x509.PublicKeyAlgorithm {
	algos := make(map[string]x509.PublicKeyAlgorithm)
	algos[x509.RSA.String()] = x509.RSA
	algos[x509.ECDSA.String()] = x509.ECDSA
	algos[x509.Ed25519.String()] = x509.Ed25519
	return algos
}

func DebugAvailableKeyAkgorithms(logger *logging.Logger) {
	algos := AvailableKeyAlgorithms()
	logger.Debug("Available Key Algorithms")
	for _, v := range algos {
		logger.Debugf("  %s", v)
	}
}
