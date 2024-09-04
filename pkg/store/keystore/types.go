package keystore

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/op/go-logging"
)

type FSExtension string
type Partition string
type Curve string
type StoreType string

type KeyHalf uint8

const (
	DEFAULT_PASSWORD = "123456"

	// Key store file backend sub directories
	PARTITION_ROOT            Partition = ""
	PARTITION_TLS             Partition = "issued"
	PARTITION_ENCRYPTION_KEYS Partition = "encryption-keys"
	PARTITION_SIGNING_KEYS    Partition = "signing-keys"
	PARTITION_HMAC            Partition = "hmac-keys"
	PARTITION_SECRETS         Partition = "secrets"

	// Key store file extensions
	FSEXT_BLOB              FSExtension = ""
	FSEXT_PRIVATE_PKCS8     FSExtension = ".key"
	FSEXT_PRIVATE_PKCS8_PEM FSExtension = ".key.pem"
	FSEXT_PUBLIC_PKCS1      FSExtension = ".pub"
	FSEXT_PUBLIC_PEM        FSExtension = ".pub.pem"
	FSEXT_PRIVATE_BLOB      FSExtension = ".key.bin"
	FSEXT_PUBLIC_BLOB       FSExtension = ".pub.bin"
	FSEXT_DIGEST            FSExtension = ".digest"
	FSEXT_SIG               FSExtension = ".sig"

	// String literals using in platform configuration file
	STORE_PKCS8   StoreType = "pkcs8"
	STORE_PKCS11  StoreType = "pkcs11"
	STORE_TPM2    StoreType = "tpm2"
	STORE_UNKNOWN StoreType = "unknown"

	CURVE_P224 Curve = "P224"
	CURVE_P256 Curve = "P256"
	CURVE_P384 Curve = "P384"
	CURVE_P521 Curve = "P521"

	KEYHALF_PRIVATE KeyHalf = 1 + iota
	KEYHALF_PUBLIC

	// Internal types not stored in the platform configuration file
	KEY_TYPE_ATTESTATION KeyType = 1 + iota
	KEY_TYPE_CA
	KEY_TYPE_ENCRYPTION
	KEY_TYPE_ENDORSEMENT
	KEY_TYPE_HMAC
	KEY_TYPE_IDEVID
	KEY_TYPE_LDEVID
	KEY_TYPE_SECRET
	KEY_TYPE_SIGNING
	KEY_TYPE_STORAGE
	KEY_TYPE_TLS
	KEY_TYPE_TPM

	ENCRYPT_ALGORITHM_RSA_PKCS1v15 = 1 + iota
	ENCRYPT_ALGORITHM_RSA_OAEP
	ENCRYPT_ALGORITHM_ECDH

	WRAP_RSA_OAEP_3072_SHA1_AES_256 WrapAlgorithm = 1 + iota
	WRAP_RSA_OAEP_4096_SHA1_AES_256
	WRAP_RSA_OAEP_3072_SHA256_AES_256
	WRAP_RSA_OAEP_4096_SHA256_AES_256
	WRAP_RSA_OAEP_3072_SHA256
	WRAP_RSA_OAEP_4096_SHA256
	WRAP_AES_GCM
)

var (
	ErrAlreadyInitialized        = errors.New("store/keystore: already initialized")
	ErrNotInitalized             = errors.New("store/keystore: not initialized")
	ErrInvalidKeyType            = errors.New("store/keystore: invalid key type")
	ErrInvalidKeyAlgorithm       = errors.New("store/keystore: invalid key algorithm")
	ErrInvalidParentAttributes   = errors.New("store/keystore: invalid parent key attributes")
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
	ErrInvalidRSAAttributes      = errors.New("store/keystore: invalid RSA key attributes")
	ErrInvalidECCAttributes      = errors.New("store/keystore: invalid ECC key attributes")
	ErrInvalidBlobName           = errors.New("store/keystore: invalid blob name")
	ErrIssuerAttributeRequired   = errors.New("store/keystore: issuer common name attribute required")
	ErrSOPinRequired             = errors.New("store/keystore: security officer PIN required")
	ErrUserPinRequired           = errors.New("store/keystore: user PIN required")
	ErrInvalidPassword           = errors.New("store/keystore: invalid password")
	ErrInvalidKeyPartition       = errors.New("store/keystore: invalid key partition")
	ErrInvalidEncodingPEM        = errors.New("store/keystore: invalid PEM encoding")
	ErrUnsupportedKeyAlgorithm   = errors.New("store/keystore: unsupported key algorithm")
	ErrPasswordRequired          = errors.New("store/keystore: password required")
)

// The Key Store Module interface
type KeyStorer interface {
	Backend() KeyBackend
	Close() error
	Delete(attrs *KeyAttributes) error
	GenerateKey(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateRSA(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateECDSA(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateEd25519(attrs *KeyAttributes) (OpaqueKey, error)
	GenerateSecretKey(attrs *KeyAttributes) error
	Decrypter(attrs *KeyAttributes) (crypto.Decrypter, error)
	Equal(opaque Opaque, x crypto.PrivateKey) bool
	Initialize(soPIN, userPIN Password) error
	Key(attrs *KeyAttributes) (OpaqueKey, error)
	Signer(attrs *KeyAttributes) (crypto.Signer, error)
	Type() StoreType
	Verifier(attrs *KeyAttributes, opts *VerifyOpts) Verifier
}

type TPMAttributes struct {
	BPublic              tpm2.TPM2BPublic
	CertHandle           tpm2.TPMHandle
	CertifyInfo          []byte
	CreationTicketDigest []byte
	Handle               tpm2.TPMHandle
	HandleType           tpm2.TPMHT
	HashAlg              tpm2.TPMIAlgHash
	Hierarchy            tpm2.TPMHandle
	HierarchyAuth        Password
	Name                 tpm2.TPM2BName
	PCRSelection         tpm2.TPMLPCRSelection
	PublicKeyBytes       []byte
	Public               tpm2.TPMTPublic
	PrivateKeyBlob       []byte
	SessionCloser        func() error
	Signature            []byte
	Template             tpm2.TPMTPublic
}

type Verifier interface {
	Verify(
		pub crypto.PublicKey,
		hash crypto.Hash,
		hashed, signature []byte,
		opts *VerifyOpts) error
}

type VerifyOpts struct {
	KeyAttributes  *KeyAttributes
	BlobCN         []byte
	IntegrityCheck bool
	PSSOptions     *rsa.PSSOptions
}

type KeyAttributes struct {
	Debug              bool
	ECCAttributes      *ECCAttributes
	CN                 string
	Hash               crypto.Hash
	KeyAlgorithm       x509.PublicKeyAlgorithm
	KeyType            KeyType
	Parent             *KeyAttributes
	Password           Password
	PlatformPolicy     bool
	RSAAttributes      *RSAAttributes
	Secret             Password
	SignatureAlgorithm x509.SignatureAlgorithm
	StoreType          StoreType
	TPMAttributes      *TPMAttributes
	WrapAttributes     *KeyAttributes
}

type ECCAttributes struct {
	Curve elliptic.Curve
}

type RSAAttributes struct {
	KeySize int
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
	case KEY_TYPE_ATTESTATION:
		return "ATTESTATION"
	case KEY_TYPE_CA:
		return "CA"
	case KEY_TYPE_ENCRYPTION:
		return "ENCRYPTION"
	case KEY_TYPE_ENDORSEMENT:
		return "ENDORSEMENT"
	case KEY_TYPE_HMAC:
		return "HMAC"
	case KEY_TYPE_IDEVID:
		return "IDevID"
	case KEY_TYPE_LDEVID:
		return "LDevID"
	case KEY_TYPE_SECRET:
		return "SECRET"
	case KEY_TYPE_SIGNING:
		return "SIGNING"
	case KEY_TYPE_STORAGE:
		return "STORAGE"
	case KEY_TYPE_TLS:
		return "TLS"
	case KEY_TYPE_TPM:
		return "TPM"
	}
	panic("store/keystore: invalid key type attribute")
}

type WrapAlgorithm uint8

func (algo WrapAlgorithm) String() string {
	switch algo {
	case WRAP_RSA_OAEP_3072_SHA1_AES_256:
		return "WRAP_RSA_OAEP_3072_SHA1_AES_256"
	case WRAP_RSA_OAEP_4096_SHA1_AES_256:
		return "WRAP_RSA_OAEP_4096_SHA1_AES_256"
	case WRAP_RSA_OAEP_3072_SHA256_AES_256:
		return "WRAP_RSA_OAEP_3072_SHA256_AES_256"
	case WRAP_RSA_OAEP_4096_SHA256_AES_256:
		return "WRAP_RSA_OAEP_4096_SHA256_AES_256"
	case WRAP_RSA_OAEP_3072_SHA256:
		return "WRAP_RSA_OAEP_3072_SHA256"
	case WRAP_RSA_OAEP_4096_SHA256:
		return "WRAP_RSA_OAEP_4096_SHA256"
	case WRAP_AES_GCM:
		return "WRAP_AES_GCM"
	}
	panic("store/keystore: invalid key wrap algorithm")
}

func DebugKeyAttributes(logger *logging.Logger, attrs *KeyAttributes) {

	var password, secret string

	if attrs.Debug {
		if attrs.Password != nil {
			var err error
			// if attrs.PlatformPolicy {
			// 	// TODO: Calling PlatformSecret.String() here causes
			// 	// an infinite loop because KeyedHashSecret lookup
			// 	// currently calls this debug method -- probably
			// 	// need to remove the calls to this method
			// 	password = "policy"
			// } else {
			// 	password, err = attrs.Password.String()
			// 	if err != nil {
			// 		logger.Error(err)
			// 	}
			// }
			if attrs.Password != nil {
				password, err = attrs.Password.String()
				if err != nil {
					logger.Error(err)
				}
			}
			if attrs.Secret != nil {
				secret, err = attrs.Secret.String()
				if err != nil {
					logger.Error(err)
				}
			}
		}
	}

	// if attrs.Parent != nil {
	// 	logger.Debug("Parent Key Attributes")
	// 	DebugKeyAttributes(logger, attrs.Parent)
	// } else {
	// 	logger.Debug("Key Attributes")
	// }

	logger.Debug("Key Attributes")

	logger.Debugf("  Common Name: %s\n", attrs.CN)
	logger.Debugf("  Debug: %t\n", attrs.Debug)
	logger.Debugf("  Hash: %s\n", attrs.Hash.String())
	logger.Debugf("  Key Algorithm: %s\n", attrs.KeyAlgorithm)
	logger.Debugf("  Platform Policy: %t\n", attrs.PlatformPolicy)
	logger.Debugf("  Signature Algorithm: %s\n", attrs.SignatureAlgorithm.String())
	logger.Debugf("  Store: %s\n", attrs.StoreType)
	logger.Debugf("  Type: %s\n", attrs.KeyType)

	if attrs.WrapAttributes != nil {
		logger.Debug("  Wrapping Key")
		logger.Debugf("   Common Name: %s\n", attrs.WrapAttributes.CN)
		logger.Debugf("   Hash: %s\n", attrs.WrapAttributes.Hash.String())
		logger.Debugf("   Key Algorithm: %s\n", attrs.WrapAttributes.KeyAlgorithm)
		logger.Debugf("   Signature Algorithm: %s\n", attrs.WrapAttributes.SignatureAlgorithm.String())
		logger.Debugf("   Type: %s\n", attrs.WrapAttributes.KeyType)
	}

	if attrs.ECCAttributes != nil {
		logger.Debug("ECC Attributes")
		logger.Debugf("  Curve: %+v", attrs.ECCAttributes.Curve.Params().Name)
	} else if attrs.RSAAttributes != nil {
		logger.Debug("RSA Attributes")
		logger.Debugf("  Size: %d", attrs.RSAAttributes.KeySize)
	}

	if attrs.Debug {
		logger.Debug("Secrets")
		logger.Debugf("  Password: %s", password)
		logger.Debugf("  Secret: %s", secret)
	}
}

func PrintKeyAttributes(attrs *KeyAttributes) {

	if attrs == nil {
		return
	}

	var password, secret string

	// if attrs.Parent != nil {
	// 	fmt.Println("Parent Key Attributes")
	// 	PrintKeyAttributes(attrs.Parent)
	// } else {
	// 	fmt.Println("Key Attributes")
	// }

	fmt.Println("Key Attributes")

	if attrs.Debug {
		if attrs.Password != nil {
			var err error
			if attrs.Password != nil {
				password, err = attrs.Password.String()
				if err != nil {
					fmt.Println(err)
				}
			}
			if attrs.Secret != nil {
				secret, err = attrs.Secret.String()
				if err != nil {
					fmt.Println(err)
				}
			}
		}
	}

	fmt.Printf("  Common Name: %s\n", attrs.CN)
	fmt.Printf("  Debug: %t\n", attrs.Debug)
	fmt.Printf("  Hash: %s\n", attrs.Hash.String())
	fmt.Printf("  Key Algorithm: %s\n", attrs.KeyAlgorithm)
	fmt.Printf("  Platform Policy: %t\n", attrs.PlatformPolicy)
	fmt.Printf("  Signature Algorithm: %s\n", attrs.SignatureAlgorithm.String())
	fmt.Printf("  Store: %s\n", attrs.StoreType)
	fmt.Printf("  Type: %s\n", attrs.KeyType)

	if attrs.WrapAttributes != nil {
		fmt.Println("  Wrapping Key")
		fmt.Printf("   Common Name: %s\n", attrs.WrapAttributes.CN)
		fmt.Printf("   Hash: %s\n", attrs.WrapAttributes.Hash.String())
		fmt.Printf("   Key Algorithm: %s\n", attrs.WrapAttributes.KeyAlgorithm)
		fmt.Printf("   Signature Algorithm: %s\n", attrs.WrapAttributes.SignatureAlgorithm.String())
		fmt.Printf("   Type: %s\n", attrs.WrapAttributes.KeyType)
	}

	if attrs.ECCAttributes != nil {
		fmt.Println("ECC Attributes")
		fmt.Printf("  Curve: %+v\n", attrs.ECCAttributes.Curve.Params().Name)
	} else if attrs.RSAAttributes != nil {
		fmt.Println("RSA Attributes")
		fmt.Printf("  Size: %d\n", attrs.RSAAttributes.KeySize)
	}

	if attrs.Debug {
		fmt.Println("Secrets")
		fmt.Printf("  Password: %s\n", password)
		fmt.Printf("  Secret: %s\n", secret)
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

// Returns a map of crypto.Hash supported by the platform
func AvailableHashes() map[string]crypto.Hash {
	hashes := make(map[string]crypto.Hash, 19)
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

// Returns a map of available signature algorithms supported by the platform
func AvailableSignatureAlgorithms() map[string]x509.SignatureAlgorithm {
	algos := make(map[string]x509.SignatureAlgorithm, 10)
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

func SignatureAlgorithmHashes() map[x509.SignatureAlgorithm]crypto.Hash {
	algos := make(map[x509.SignatureAlgorithm]crypto.Hash, 10)
	algos[x509.SHA256WithRSA] = crypto.SHA256
	algos[x509.SHA384WithRSA] = crypto.SHA384
	algos[x509.SHA512WithRSA] = crypto.SHA512
	algos[x509.ECDSAWithSHA256] = crypto.SHA256
	algos[x509.ECDSAWithSHA384] = crypto.SHA384
	algos[x509.ECDSAWithSHA512] = crypto.SHA512
	algos[x509.SHA256WithRSAPSS] = crypto.SHA256
	algos[x509.SHA384WithRSAPSS] = crypto.SHA384
	algos[x509.SHA512WithRSAPSS] = crypto.SHA512
	algos[x509.PureEd25519] = 0
	return algos
}

func DebugAvailableSignatureAkgorithms(logger *logging.Logger) {
	algos := AvailableSignatureAlgorithms()
	logger.Debug("Available Signature Algorithms")
	for _, v := range algos {
		logger.Debugf("  %s", v)
	}
}

// Returns a map of available key algorithms supported by the platform
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

// Converts crypto.Hash to platform file extension prefix
func FSHashName(hash crypto.Hash) string {
	name := strings.ToLower(hash.String())
	name = strings.ReplaceAll(name, "-", "")
	return strings.ReplaceAll(name, "/", "")
}

// Prefixes a key algorithm name to file extension
func KeyFileExtension(
	algo x509.PublicKeyAlgorithm,
	extension FSExtension,
	keyType *KeyType) FSExtension {

	keyExt := FSEXTKeyAlgorithm(algo)
	if keyType != nil && *keyType == KEY_TYPE_HMAC {
		return FSExtension(fmt.Sprintf("%s.hmac%s", keyExt, extension))
	}
	return FSExtension(fmt.Sprintf("%s%s", keyExt, extension))
}

// Converts an x509.PublicKeyAlgorithm to a platform file extension
func FSEXTKeyAlgorithm(algo x509.PublicKeyAlgorithm) string {
	return fmt.Sprintf(".%s", strings.ToLower(algo.String()))
}

// Converts keystore.KeyAttributes to a platform file extension
func FSKeyExtension(attrs KeyAttributes, ext FSExtension) string {
	return fmt.Sprintf("%s%s", FSEXTKeyAlgorithm(attrs.KeyAlgorithm), ext)
}

// Converts a hash function name to a file extension. Used to
// save a signed digest file with an appropriate file extension
// to the blob
func HashFileExtension(hash crypto.Hash) string {
	return fmt.Sprintf(".%s", FSHashName(hash))
}

// Returns true if the signature algorithm is one of RSA PSS
func IsRSAPSS(sigAlgo x509.SignatureAlgorithm) bool {
	switch sigAlgo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	}
	return false
}
