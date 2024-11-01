package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

type TrustedPlatformModule interface {
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)
	AKProfile() (AKProfile, error)
	CalculateName(algID tpm2.TPMAlgID, publicArea []byte)
	Clear(hierarchyAuth []byte, hierarchy tpm2.TPMHandle) error
	Close() error
	Config() *Config
	CreateECDSA(
		keyAttrs *keystore.KeyAttributes,
		backend keystore.KeyBackend) (*ecdsa.PublicKey, error)
	CreateEK(keyAttrs *keystore.KeyAttributes) error
	CreateSecretKey(
		keyAttrs *keystore.KeyAttributes,
		backend keystore.KeyBackend) error
	CreateIAK(ekAttrs *keystore.KeyAttributes) (*keystore.KeyAttributes, error)
	CreateIDevID(akAttrs *keystore.KeyAttributes, ekCert *x509.Certificate) (*keystore.KeyAttributes, *TCG_CSR_IDEVID, error)
	CreatePlatformPolicy() error
	CreateRSA(
		keyAttrs *keystore.KeyAttributes,
		backend keystore.KeyBackend) (*rsa.PublicKey, error)
	CreateKeySession(
		keyAttrs *keystore.KeyAttributes) (tpm2.Session, func() error, error)
	CreateSession(
		keyAttrs *keystore.KeyAttributes) (tpm2.Session, func() error, error)
	CreateSRK(keyAttrs *keystore.KeyAttributes) error
	CreateTCG_CSR_IDEVID(
		ekCert *x509.Certificate,
		akAttrs *keystore.KeyAttributes,
		idevidAttrs *keystore.KeyAttributes) (TCG_CSR_IDEVID, error)
	DeleteKey(keyAttrs *keystore.KeyAttributes, backend keystore.KeyBackend) error
	Device() string
	EK() crypto.PublicKey
	EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic)
	EKAttributes() (*keystore.KeyAttributes, error)
	EKCertificate() (*x509.Certificate, error)
	EKECC() *ecdsa.PublicKey
	EKRSA() *rsa.PublicKey
	EventLog() ([]byte, error)
	FixedProperties() (*PropertiesFixed, error)
	Flush(handle tpm2.TPMHandle)
	GoldenMeasurements() []byte
	HMAC(auth []byte) tpm2.Session
	HMACSaltedSession(
		handle tpm2.TPMHandle,
		pub tpm2.TPMTPublic,
		auth []byte) (s tpm2.Session, close func() error, err error)
	HMACSession(auth []byte) (s tpm2.Session, close func() error, err error)
	IAK() crypto.PublicKey
	IAKAttributes() (*keystore.KeyAttributes, error)
	IDevID() crypto.PublicKey
	IDevIDAttributes() (*keystore.KeyAttributes, error)
	Info() (string, error)
	IsFIPS140_2() (bool, error)
	Install(soPIN keystore.Password) error
	KeyAttributes(handle tpm2.TPMHandle) (*keystore.KeyAttributes, error)
	LoadKeyPair(
		keyAttrs *keystore.KeyAttributes,
		session *tpm2.Session,
		backend keystore.KeyBackend) (*tpm2.LoadResponse, error)
	MakeCredential(
		akName tpm2.TPM2BName,
		secret []byte) ([]byte, []byte, []byte, error)
	NonceSession(secret keystore.Password) (tpm2.Session, func() error, error)
	NVRead(keyAttrs *keystore.KeyAttributes, dataSize uint16) ([]byte, error)
	NVWrite(keyAttrs *keystore.KeyAttributes) error
	Open() error
	ParseEKCertificate(ekCert []byte) (*x509.Certificate, error)
	ParsePublicKey(tpm2BPublic []byte) (crypto.PublicKey, error)
	PlatformPolicyDigestHash() ([]byte, error)
	PlatformPolicyDigest() tpm2.TPM2BDigest
	PlatformPolicySession() (tpm2.Session, func() error, error)
	PlatformQuote(keyAttrs *keystore.KeyAttributes) (Quote, []byte, error)
	Provision(soPIN keystore.Password) error
	ProvisionEKCert(hierarchyAuth, ekCert []byte) error
	ProvisionOwner(hierarchyAuth keystore.Password) (*keystore.KeyAttributes, error)
	Quote(pcrs []uint, nonce []byte) (Quote, error)
	Random() ([]byte, error)
	RandomBytes(fixedLength int) ([]byte, error)
	RandomHex(fixedLength int) ([]byte, error)
	Read(data []byte) (n int, err error)
	ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error)
	ReadPCRs(pcrList []uint) ([]PCRBank, error)
	SaveKeyPair(
		keyAttrs *keystore.KeyAttributes,
		outPrivate tpm2.TPM2BPrivate,
		outPublic tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic],
		backend keystore.KeyBackend) error
	Seal(
		keyAttrs *keystore.KeyAttributes,
		backend keystore.KeyBackend) (*tpm2.CreateResponse, error)
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	SetHierarchyAuth(oldSecret, newSecret keystore.Password, hierarchy *tpm2.TPMHandle) error
	SecretFromShares(shares []string) (string, error)
	ShareSecret(secret []byte, shares int) ([]string, error)
	SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic)
	SSRKAttributes() (*keystore.KeyAttributes, error)
	Transport() transport.TPM
	Unseal(keyAttrs *keystore.KeyAttributes, backend keystore.KeyBackend) ([]byte, error)
	WriteEKCert(ekCert []byte) error

	VerifyTCG_CSR_IAK(
		csr *TCG_CSR_IDEVID,
		sigAlgo x509.SignatureAlgorithm) (*keystore.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error)
	SignValidate(
		keyAttrs *keystore.KeyAttributes,
		digest, validationDigest []byte) ([]byte, error)
	HashSequence(
		keyAttrs *keystore.KeyAttributes,
		data []byte) ([]byte, []byte, error)
}

type Params struct {
	Backend      keystore.KeyBackend
	BlobStore    blob.BlobStorer
	CertStore    certstore.CertificateStorer
	Config       *Config
	DebugSecrets bool
	FQDN         string
	Logger       *logging.Logger
	SignerStore  keystore.SignerStorer
}

type TPM2 struct {
	backend      keystore.KeyBackend
	blobStore    blob.BlobStorer
	certStore    certstore.CertificateStorer
	config       *Config
	debugSecrets bool
	device       *os.File
	ekAttrs      *keystore.KeyAttributes
	ekECCPubKey  *ecdsa.PublicKey
	ekRSAPubKey  *rsa.PublicKey
	fqdn         string
	hash         crypto.Hash
	iakAttrs     *keystore.KeyAttributes
	idevidAttrs  *keystore.KeyAttributes
	logger       *logging.Logger
	policyDigest tpm2.TPM2BDigest
	signerStore  keystore.SignerStorer
	simulator    *simulator.Simulator
	ssrkAttrs    *keystore.KeyAttributes
	transport    transport.TPM
	TrustedPlatformModule
}

// Creates a new TPM2 instance by opening a socket to a
// Trusted Platform Module (TPM). When this function
// returns the TPM is ready for use.
func NewTPM2(params *Params) (TrustedPlatformModule, error) {

	if params.Config == nil || params.Config.Device == "" {
		params.Config.Device = "/dev/tpmrm0"
	}

	if params.Config.EK.KeyAlgorithm == "" {
		if params.Config.EK.RSAConfig != nil {
			params.Config.EK.KeyAlgorithm = x509.RSA.String()
		} else if params.Config.EK.ECCConfig != nil {
			params.Config.EK.KeyAlgorithm = x509.ECDSA.String()
		} else {
			return nil, keystore.ErrInvalidKeyAttributes
		}
	}

	var sim *simulator.Simulator
	var tpmTransport transport.TPM
	var device *os.File
	var err error
	if params.Config.UseSimulator {
		params.Logger.Info(infoOpeningSimulator)
		sim, err = simulator.GetWithFixedSeedInsecure(1234567890)
		if err != nil {
			params.Logger.Error(err)
			return nil, err
		}
		tpmTransport = transport.FromReadWriter(sim)
	} else {
		params.Logger.Info(infoOpeningDevice,
			slog.String("device", params.Config.Device))
		device, err = os.OpenFile(params.Config.Device, os.O_RDWR, 0)
		if err != nil {
			params.Logger.Error(err)
			return nil, ErrOpeningDevice
		}
		tpmTransport = transport.FromReadWriter(device)
	}

	hash, ok := keystore.AvailableHashes()[params.Config.Hash]
	if !ok {
		return nil, keystore.ErrInvalidHashFunction
	}

	tpm := &TPM2{
		logger:       params.Logger,
		backend:      params.Backend,
		blobStore:    params.BlobStore,
		certStore:    params.CertStore,
		signerStore:  params.SignerStore,
		debugSecrets: params.DebugSecrets,
		config:       params.Config,
		device:       device,
		fqdn:         params.FQDN,
		hash:         hash,
		simulator:    sim,
		transport:    tpmTransport}

	// Return ErrNotInitialized if the EK persistent handle can't be read
	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(params.Config.EK.Handle),
	}.Execute(tpm.transport)
	if err != nil {
		if err == tpm2.TPMRC(0x184) {
			// TPM_RC_VALUE (handle 1): value is out of range or is not correct for the context
			return tpm, ErrNotInitialized
		} else if err == tpm2.TPMRC(0x18b) {
			// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
			return tpm, ErrNotInitialized
		} else {
			tpm.logger.Error(err)
			return nil, err
		}
	}

	return tpm, nil
}

// Opens a new logical connection with the underlying TPM
// using an instance of this TPM2 object that's already been
// instantiated.
func (tpm *TPM2) Open() error {

	var t transport.TPM

	if tpm.config.UseSimulator {

		tpm.logger.Info(infoOpeningSimulator)
		sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
		if err != nil {
			tpm.logger.Error(err)
			return err
		}
		tpm.simulator = sim
		t = transport.FromReadWriter(sim)
	} else {
		tpm.logger.Info(infoOpeningDevice, slog.String("device", tpm.config.Device))
		f, err := os.OpenFile(tpm.config.Device, os.O_RDWR, 0)
		if err != nil {
			tpm.logger.Error(err)
			return ErrOpeningDevice
		}
		tpm.device = f
		t = transport.FromReadWriter(f)
	}

	tpm.transport = t
	return nil
}

// Parses a tpm2.TPM2BPublic byte array and returns the crypto.PublicKey
func (tpm *TPM2) ParsePublicKey(tpm2BPublic []byte) (crypto.PublicKey, error) {

	loadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](tpm2BPublic),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	defer tpm.Flush(loadRsp.ObjectHandle)

	pubArea, err := tpm2.ReadPublic{
		ObjectHandle: loadRsp.ObjectHandle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	pub, err := pubArea.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	if pub.Type == tpm2.TPMAlgRSA {
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, err
		}
		return rsaPub, nil

	} else if pub.Type == tpm2.TPMAlgECC {

		eccDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, err
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return nil, err
		}

		curve, err := eccDetail.CurveID.Curve()
		if err != nil {
			return nil, err
		}

		eccPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

		return eccPub, nil
	}

	return nil, keystore.ErrInvalidKeyAlgorithm
}

// Returns the platform policy digest used to satisfy
// platform PCR authorization values
func (tpm *TPM2) PlatformPolicyDigest() tpm2.TPM2BDigest {
	if tpm.policyDigest.Buffer == nil {
		_, closer, err := tpm.PlatformPolicySession()
		if err != nil {
			tpm.logger.FatalError(err)
		}
		defer closer()
	}
	return tpm.policyDigest
}

// Returns the TPM device path
func (tpm *TPM2) Device() string {
	return tpm.config.Device
}

// Returns the underlying transport.TPM used to facilitate
// the logical connection to the TPM.
func (tpm *TPM2) Transport() transport.TPM {
	return tpm.transport
}

// Closes the connection to the TPM
func (tpm *TPM2) Close() error {
	tpm.logger.Info(infoClosingConnection)
	if tpm.device != nil {
		if err := tpm.device.Close(); err != nil {
			tpm.logger.Error(err)
		}
		tpm.device = nil
		tpm.transport = nil
	}
	if tpm.simulator != nil {
		tpm.simulator.Close()
		tpm.simulator = nil
	}
	return nil
}

// Returns the TPM configuration per the platform configuration file
func (tpm *TPM2) Config() *Config {
	return tpm.config
}

// Takes ownership of the TPM by setting the Owner, Endorsement and
// Lockout hierarchy authorization passwords, as described in TCG
// TPM 2.0 Part 1 - Architecture - Section 13.8.1 - Taking Ownership
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
//
// If the optional hierarchy is provided, only the authorization password for
// the specified hierarchy will be set. If not provided, all hierarchies will
// be set to the same authorization password.
func (tpm *TPM2) SetHierarchyAuth(oldPasswd, newPasswd keystore.Password, hierarchy *tpm2.TPMHandle) error {
	if hierarchy != nil {
		var sHierarchy string
		switch *hierarchy {
		case tpm2.TPMRHLockout:
			sHierarchy = "Lockout"
		case tpm2.TPMRHEndorsement:
			sHierarchy = "Endorsement"
		case tpm2.TPMRHOwner:
			sHierarchy = "Owner"
		}
		tpm.logger.Debug("tpm: Setting hierarchy authorization password",
			slog.String("hierarchy", sHierarchy))
	} else {
		tpm.logger.Debug("tpm: Setting hierarchy authorization passwords")
	}
	var oldPassword, newPassword []byte
	var err error
	if oldPasswd != nil {
		oldPassword, err = oldPasswd.Bytes()
		if err != nil {
			return err
		}
	}
	if newPasswd != nil {
		newPassword, err = newPasswd.Bytes()
		if err != nil {
			return err
		}
	}
	if tpm.debugSecrets {
		tpm.logger.Debug(
			"tpm: passwords",
			slog.String("old", string(oldPassword)),
			slog.String("new", string(newPassword)))
	}
	var hierarchies []tpm2.TPMHandle
	if hierarchy != nil {
		hierarchies = []tpm2.TPMHandle{
			*hierarchy,
		}
	} else {
		hierarchies = []tpm2.TPMHandle{
			tpm2.TPMRHEndorsement,
			tpm2.TPMRHLockout,
			tpm2.TPMRHOwner,
			// tpm2.TPMRHPlatform,
		}
	}
	for _, hierarchy := range hierarchies {
		_, err := tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{
				Handle: hierarchy,
				Auth:   tpm2.PasswordAuth(oldPassword),
			},
			NewAuth: tpm2.TPM2BAuth{
				Buffer: newPassword,
			},
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error(err)
			return err
		}
	}
	return nil
}

// Retrieve the requested Endorsement Key Certificate from the Certificate
// Authority signed blob store. If the certificate can not be found, treat
// this as an initial setup and try to load the cert from TPM NVRAM. If that
// fails, try to download the certificate from the Manufacturer's EK cert
// service. If that fails, try to load the certificate from the current
// working directory as a final attempt, using the EKCert name defined
// in the platform configuration file.
func (tpm *TPM2) EKCertificate() (*x509.Certificate, error) {

	tpm.logger.Debug("tpm: retrieving EK certificate")

	policyDigest := tpm.PlatformPolicyDigest()
	ekAttrs, err := EKAttributesFromConfig(*tpm.config.EK, &policyDigest)
	if err != nil {
		return nil, err
	}

	if tpm.config.EK.CertHandle == 0 {
		ekCert, err := tpm.certStore.Get(ekAttrs)
		if err != nil {
			if err == certstore.ErrCertNotFound {
				return nil, ErrEndorsementCertNotFound
			}
			return nil, err
		}
		return ekCert, nil
	}

	// Load the EK cert
	var ekCertIndex tpm2.TPMHandle
	if ekAttrs.TPMAttributes != nil && ekAttrs.TPMAttributes.CertHandle > 0 {
		// ... using EK cert index provided by TPM attributes
		ekCertIndex = tpm2.TPMHandle(ekAttrs.TPMAttributes.CertHandle)

	} else if tpm.config.EK.CertHandle > 0 {

		// ... using Load EK cert index provided by platform configuration
		ekCertIndex = tpm2.TPMHandle(tpm.config.EK.CertHandle)

	} else {

		// Load the EK cert using the recommended indexes for
		// the key algorithm
		if ekAttrs.KeyAlgorithm == x509.RSA {
			ekCertIndex = tpm2.TPMHandle(ekCertIndexRSA2048)
		} else if ekAttrs.KeyAlgorithm == x509.ECDSA {
			ekCertIndex = tpm2.TPMHandle(ekCertIndexECCP256)
		} else {
			return nil, keystore.ErrInvalidKeyAlgorithm
		}
	}

	// Read the EK cert from NVRAM
	response, err := tpm2.NVReadPublic{
		NVIndex: ekCertIndex,
	}.Execute(tpm.transport)
	if err != nil {

		tpm.logger.Error(err)

		// As a last resort, try downloading from the manufacturer
		// EK certificate service
		manufacuterCert, err := tpm.downloadEKCertFromManufacturer(ekCertIndex)
		if err == nil && len(manufacuterCert) > 0 {
			return x509.ParseCertificate(manufacuterCert)
		}

		return nil, ErrEndorsementCertNotFound
	}

	return x509.ParseCertificate(response.NVPublic.Bytes())
}

// Signs the requested data using the key attributes
// provided by SignerOpts. Supports RSA and ECDSA.
func (tpm *TPM2) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	ksSignerOpts, ok := opts.(*keystore.SignerOpts)
	if !ok {
		return nil, keystore.ErrInvalidSignerOpts
	}

	var session tpm2.Session
	var closer func() error

	keyAttrs := ksSignerOpts.KeyAttributes

	if keyAttrs.Parent == nil {
		return nil, keystore.ErrInvalidParentAttributes
	}

	// Default to the platform backend
	backend := tpm.backend

	// Use backend provided by signer opts
	if ksSignerOpts.Backend != nil {
		backend = ksSignerOpts.Backend
	}

	// Create parent session to load the key
	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		if closer != nil {
			closer()
		}
		return nil, err
	}
	defer closer()

	var handle tpm2.TPMHandle

	validation := tpm2.TPMTTKHashCheck{
		Tag: tpm2.TPMSTHashCheck,
	}

	if keyAttrs.KeyType == keystore.KEY_TYPE_ATTESTATION ||
		keyAttrs.KeyType == keystore.KEY_TYPE_IDEVID {

		digest, validationDigest, err := tpm.Hash(keyAttrs, digest)

		// TPMT_TK_HASHCHECK – This ticket is used to indicate that
		// a digest of external data is safe to sign using a restricted
		// signing key. A restricted signing key may only sign a digest
		// that was produced by the TPM. If the digest was produced from
		// externally provided data, there needs to be an indication that the
		// data did not start with the same first octets as are used for data
		// that is generated within the TPM. This prevents "forgeries" of
		// attestation data. This ticket is used to provide the evidence that
		// the data used in the digest was checked by the TPM and is safe to
		// sign. Assuming that the external data is "safe", this type of ticket
		// is produced by TPM2_Hash() or TPM2_SequenceComplete() and used by
		// TPM2_Sign().
		validation = tpm2.TPMTTKHashCheck{
			Hierarchy: tpm2.TPMRHEndorsement,
			Digest: tpm2.TPM2BDigest{
				Buffer: validationDigest,
			},
			Tag: tpm2.TPMSTHashCheck,
		}

		handle = keyAttrs.TPMAttributes.Handle

		pub, err := tpm2.ReadPublic{
			ObjectHandle: handle,
		}.Execute(tpm.Transport())
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}

		outPub, err := pub.OutPublic.Contents()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}

		var algo tpm2.TPMIAlgHash
		if opts == nil {
			algo = tpm2.TPMAlgSHA256
		} else {
			if opts.HashFunc() == crypto.SHA256 {
				algo = tpm2.TPMAlgSHA256
			} else if opts.HashFunc() == crypto.SHA384 {
				algo = tpm2.TPMAlgSHA384
			} else if opts.HashFunc() == crypto.SHA512 {
				algo = tpm2.TPMAlgSHA512
			} else {
				tpm.logger.Errorf("%s: %s",
					keystore.ErrInvalidHashFunction, opts.HashFunc())
				return nil, keystore.ErrInvalidHashFunction
			}
		}

		rsaDetails, err := outPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rsaDetails.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(
					rsaDetails.Scheme.Scheme, &tpm2.TPMSSchemeHash{
						HashAlg: algo,
					}),
			},
			Validation: validation,
		}.Execute(tpm.transport)
		if err != nil {
			return nil, err
		}
		var rsaSig *tpm2.TPMSSignatureRSA
		if opts.(*keystore.SignerOpts).PSSOptions != nil {
			rsaSig, err = signResponse.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}
		} else {
			rsaSig, err = signResponse.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}
		}
		return rsaSig.Sig.Buffer, nil

	} else {

		// Load the keyed hash from saved context file and priv, pub keys
		key, err := tpm.LoadKeyPair(keyAttrs, &session, backend)
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		defer tpm.Flush(key.ObjectHandle)
		handle = key.ObjectHandle
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm.Transport())
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	outPub, err := pub.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	var algo tpm2.TPMIAlgHash
	if opts == nil {
		algo = tpm2.TPMAlgSHA256
	} else {
		if opts.HashFunc() == crypto.SHA256 {
			algo = tpm2.TPMAlgSHA256
		} else if opts.HashFunc() == crypto.SHA384 {
			algo = tpm2.TPMAlgSHA384
		} else if opts.HashFunc() == crypto.SHA512 {
			algo = tpm2.TPMAlgSHA512
		} else {
			tpm.logger.Errorf("%s: %s",
				keystore.ErrInvalidHashFunction, opts.HashFunc())
			return nil, keystore.ErrInvalidHashFunction
		}
	}

	// Create key session to sign with
	session2, closer2, err2 := tpm.CreateKeySession(keyAttrs)
	if err2 != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer2()

	if outPub.Type == tpm2.TPMAlgRSA {

		rsaDetails, err := outPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   session2,
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rsaDetails.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(
					rsaDetails.Scheme.Scheme, &tpm2.TPMSSchemeHash{
						HashAlg: algo,
					}),
			},
			Validation: validation,
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}

		var rsaSig *tpm2.TPMSSignatureRSA
		if keystore.IsRSAPSS(keyAttrs.SignatureAlgorithm) ||
			opts.(*keystore.SignerOpts).PSSOptions != nil {

			rsaSig, err = signResponse.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}

			pubKey, err := tpm.ParsePublicKey(pub.OutPublic.Bytes())
			if err != nil {
				return nil, err
			}
			err = rsa.VerifyPSS(
				pubKey.(*rsa.PublicKey),
				crypto.SHA256,
				digest,
				rsaSig.Sig.Buffer,
				&rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				})
			if err != nil {
				return nil, err
			}
			fips140_2, err := tpm.IsFIPS140_2()
			if err != nil {
				return nil, err
			}
			if !fips140_2 {
				// TPM's that aren't FIPS 140-2 compliant don't sign
				// RSA-PSS using a salt length the same size as the
				// hash length, which is incompatible with TLS v1.3
				// and non-compliant with FIPS 140-2.
				//
				// The Golang crypto/rsa/pss.go doesn't expose a public
				// API to perform PSS padding, so punting on synthesizing
				// the functionality on behalf of incompatible TPMs for now.
				tpm.logger.FatalError(ErrRSAPSSNotSupported)
			}

		} else {
			rsaSig, err = signResponse.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}
		}
		return rsaSig.Sig.Buffer, nil

	} else if outPub.Type == tpm2.TPMAlgECC {

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   session2,
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSchemeHash{
						HashAlg: algo,
					},
				),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(tpm.Transport())
		if err != nil {
			return nil, err
		}

		sig, err := signResponse.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}
		return asn1.Marshal(asn1Struct)
	}

	return nil, keystore.ErrUnsupportedKeyAlgorithm
}

// Performs a TPM2_Hash on the requested data. If the length is greater
// than 1024 bytes, the data is hashed using HashSequence commands.
func (tpm *TPM2) Hash(
	keyAttrs *keystore.KeyAttributes,
	data []byte) ([]byte, []byte, error) {

	if len(data) > 1024 {
		return tpm.HashSequence(keyAttrs, data)
	}
	h, err := tpm2.Hash{
		Hierarchy: tpm2.TPMRHEndorsement,
		HashAlg:   keyAttrs.TPMAttributes.HashAlg,
		Data: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	return h.OutHash.Buffer, h.Validation.Digest.Buffer, nil
}

// Performs a hash sequence using TPM2_HashSequenceStart,
// TPM2_SequenceUpdate, TPM2_SequenceComplete under the
// Endorsement Hierarchy, using the Hierarchy Authorization
// provided in the key attributes Parent field.
func (tpm *TPM2) HashSequence(
	keyAttrs *keystore.KeyAttributes,
	data []byte) ([]byte, []byte, error) {

	// var auth []byte
	var err error
	var maxDigestBuffer = 1024

	// if keyAttrs.Password != nil {
	// 	auth, err = keyAttrs.Password.Bytes()
	// 	if err != nil {
	// 		return nil, nil, err
	// 	}
	// }

	hierarchyAuth, err := keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	if err != nil {
		return nil, nil, err
	}

	auth := hierarchyAuth

	hashSequenceStart := tpm2.HashSequenceStart{
		Auth: tpm2.TPM2BAuth{
			Buffer: auth,
		},
		HashAlg: keyAttrs.TPMAttributes.HashAlg,
	}
	rspHSS, err := hashSequenceStart.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}

	authHandle := tpm2.AuthHandle{
		Handle: rspHSS.SequenceHandle,
		Name: tpm2.TPM2BName{
			Buffer: auth,
		},
		Auth: tpm2.PasswordAuth(hierarchyAuth),
	}

	for len(data) > maxDigestBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxDigestBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(tpm.transport)
		if err != nil {
			return nil, nil, err
		}

		data = data[maxDigestBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHEndorsement,
	}

	rspSC, err := sequenceComplete.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	digest := rspSC.Result.Buffer

	return digest, rspSC.Validation.Digest.Buffer, nil
}

// Performs a sequential hash on the provided data using the
// hash algorithm and authorization defined by akAttrs. This
// operation uses the Handle, HashAlg, Name, SignatureAlgorithm
// and Password provided by akAttrs.
func (tpm *TPM2) SignValidate(
	keyAttrs *keystore.KeyAttributes,
	digest, validationDigest []byte) ([]byte, error) {

	var akAuth []byte
	var err error

	if keyAttrs.Password != nil {
		akAuth, err = keyAttrs.Password.Bytes()
		if err != nil {
			return nil, err
		}
	}

	// Sign the digest
	var hashSig []byte
	if keyAttrs.TPMAttributes.Public.Type == tpm2.TPMAlgRSA {

		// rsaDetails, err := keyAttrs.TPMAttributes.Public.Parameters.RSADetail()
		rsaDetails, err := keyAttrs.TPMAttributes.Public.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: keyAttrs.TPMAttributes.Handle,
				Name:   keyAttrs.TPMAttributes.Name,
				Auth:   tpm2.PasswordAuth(akAuth),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rsaDetails.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(
					rsaDetails.Scheme.Scheme, &tpm2.TPMSSchemeHash{
						HashAlg: keyAttrs.TPMAttributes.HashAlg,
					}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Hierarchy: tpm2.TPMRHEndorsement,
				Digest: tpm2.TPM2BDigest{
					Buffer: validationDigest,
				},
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}

		var rsaSig *tpm2.TPMSSignatureRSA
		if keystore.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
			rsaSig, err = signResponse.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}
		} else {
			rsaSig, err = signResponse.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}

			// loadRsp, err := tpm2.LoadExternal{
			// 	Hierarchy: tpm2.TPMRHEndorsement,
			// 	// InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](tcgContent.AttestPub),
			// 	// InPublic: akAttrs.TPMAttributes.BPublic,
			// 	InPublic: tpm2.New2B(keyAttrs.TPMAttributes.Public),
			// 	// InPublic: tpm2.New2B(*iakPub),
			// }.Execute(tpm.transport)
			// if err != nil {
			// 	return nil, err
			// }
			// defer tpm.Flush(loadRsp.ObjectHandle)

			// _, err = tpm2.VerifySignature{
			// 	KeyHandle: loadRsp.ObjectHandle,
			// 	Digest: tpm2.TPM2BDigest{
			// 		Buffer: digest,
			// 	},
			// 	Signature: tpm2.TPMTSignature{
			// 		SigAlg: tpm2.TPMAlgRSASSA,
			// 		Signature: tpm2.NewTPMUSignature[*tpm2.TPMSSignatureRSA](
			// 			tpm2.TPMAlgRSASSA,
			// 			&tpm2.TPMSSignatureRSA{
			// 				Hash: keyAttrs.TPMAttributes.HashAlg,
			// 				Sig: tpm2.TPM2BPublicKeyRSA{
			// 					Buffer: rsaSig.Sig.Buffer,
			// 				},
			// 			},
			// 		),
			// 	},
			// }.Execute(tpm.transport)
			// if err != nil {
			// 	return nil, err
			// }

		}
		hashSig = rsaSig.Sig.Buffer

	} else if keyAttrs.TPMAttributes.Public.Type == tpm2.TPMAlgECC {

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: keyAttrs.TPMAttributes.Handle,
				Name:   keyAttrs.TPMAttributes.Name,
				Auth:   tpm2.PasswordAuth(akAuth),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSchemeHash{
						HashAlg: keyAttrs.TPMAttributes.HashAlg,
					},
				),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Hierarchy: tpm2.TPMRHEndorsement,
				Digest: tpm2.TPM2BDigest{
					Buffer: validationDigest,
				},
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(tpm.transport)
		if err != nil {
			return nil, err
		}

		sig, err := signResponse.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}

		asn1Sig, err := asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, err
		}
		hashSig = asn1Sig
	}

	return hashSig, nil
}

// Retrieves the raw event log from /sys/kernel/security/tpm*/binary_bios_measurements
func (tpm *TPM2) EventLog() ([]byte, error) {
	measurementLogPath := fmt.Sprintf(
		"/sys/kernel/security/%s/binary_bios_measurements",
		tpm.tpmDeviceName())
	bytes, err := os.ReadFile(measurementLogPath)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return bytes, nil
}

// Returns the name and public area for the provided handle
func (tpm *TPM2) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	ek, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm.transport)
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, err
	}
	pub, err := ek.OutPublic.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, err
	}
	return ek.Name, *pub, nil
}

// Reads Platform Configuration Register (PCR) values across all
// supported banks with the corresponding PCR ID. This method supports SHA1,
// SHA256, SHA386, and SHA512. If one of the banks are not supported, the
// function stops processing and returns the banks that were successfully
// parsed without an error.
func (tpm *TPM2) ReadPCRs(pcrList []uint) ([]PCRBank, error) {

	tpm.logger.Debugf("tpm/ReadPCRs: Reading PCR values across all supported banks")

	maxPCR := uint(23)
	banks := make([]PCRBank, 0)

	supportedBanks := make(map[string]tpm2.TPMAlgID, 4)
	supportedBanks["SHA1"] = tpm2.TPMAlgSHA1
	supportedBanks["SHA256"] = tpm2.TPMAlgSHA256
	supportedBanks["SHA386"] = tpm2.TPMAlgSHA384
	supportedBanks["SHA512"] = tpm2.TPMAlgSHA512

Exit:
	for name, algo := range supportedBanks {

		tpm.logger.Debug(name)

		bank := PCRBank{
			Algorithm: name,
			PCRs:      make([]PCR, 0),
		}
		for i, pcr := range pcrList {
			if pcr > maxPCR {
				return nil, ErrInvalidPCRIndex
			}
			pcrRead := tpm2.PCRRead{
				PCRSelectionIn: tpm2.TPMLPCRSelection{
					PCRSelections: []tpm2.TPMSPCRSelection{
						{
							Hash:      algo,
							PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
						},
					},
				},
			}
			response, err := pcrRead.Execute(tpm.transport)
			if err != nil {
				if strings.Contains(err.Error(), ErrHashAlgorithmNotSupported.Error()) {
					tpm.logger.Warnf("tpm/ReadPCRs: error reading PCR Bank %s: %s", algo, err)
					return banks, nil
				}
			}
			if response == nil {
				if strings.Contains(err.Error(), "hash algorithm not supported or not appropriate") {
					break Exit
				}
				tpm.logger.Errorf("tpm/ReadPCRs: error reading PCR bank %s: %s", name, err)
				return banks, nil
			}
			buf := response.PCRValues.Digests[0].Buffer
			encoded := []byte(Encode(buf))
			bank.PCRs = append(bank.PCRs, PCR{
				ID:    int32(i),
				Value: encoded,
			})
			tpm.logger.Debugf("  %d: 0x%s", pcr, encoded)
		}
		banks = append(banks, bank)
	}
	return banks, nil
}

// Flushes a handle from TPM memory
func (tpm *TPM2) Flush(handle tpm2.TPMHandle) {
	tpm.logger.Debugf("tpm: flushing handle: 0x%x", handle)
	_, err := tpm2.FlushContext{FlushHandle: handle}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
	}
}

// Thanks, Google:
// https://github.com/google/go-attestation/blob/master/attest/tpm.go#L263
func intelEKURL(ekPub *rsa.PublicKey) string {
	pubHash := sha256.New()
	pubHash.Write(ekPub.N.Bytes())
	pubHash.Write([]byte{0x1, 0x00, 0x01})

	return intelEKCertServiceURL + url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))
}

// Downloads the EK certificate from the manufactuers EK cert service
func (tpm *TPM2) downloadEKCertFromManufacturer(ekCertIndex tpm2.TPMHandle) ([]byte, error) {

	attrs, err := tpm.KeyAttributes(tpm2.TPMHandle(ekIndex))
	if err != nil {
		return nil, err
	}

	ekPub := attrs.TPMAttributes.Public

	if ekPub.Type != tpm2.TPMAlgRSA {
		return nil, errors.New("ECC EK certificates unsupported at this time")
	}

	rsaDetail, err := ekPub.Parameters.RSADetail()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaUnique, err := ekPub.Unique.RSA()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	url := intelEKURL(rsaPub)
	tpm.logger.Infof("tpm: downloading EK certificate from %s", url)

	resp, err := http.Get(url)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	if resp.StatusCode != 200 {
		body := new(strings.Builder)
		_, err := io.Copy(body, resp.Body)
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		tpm.logger.Errorf("tpm: error downloading EK certificate: httpm.StatusCode: %d, body: %s",
			resp.StatusCode, body)
		return nil, ErrEndorsementCertNotFound
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, resp.Body); err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	return buf.Bytes(), nil
}

func (tpm *TPM2) tpmDeviceName() string {
	filename := filepath.Base(tpm.config.Device)
	return strings.ReplaceAll(filename, "tpmrm", "tpm")
}

// Calculates the key name of the provided public area using the specified algorithm
func CalculateName(algID tpm2.TPMAlgID, publicArea []byte) ([]byte, error) {
	var hash []byte
	switch algID {
	case tpm2.TPMAlgSHA1:
		h := sha1.New()
		h.Write(publicArea)
		hash = h.Sum(nil)
	case tpm2.TPMAlgSHA256:
		h := sha256.New()
		h.Write(publicArea)
		hash = h.Sum(nil)
	case tpm2.TPMAlgSHA3384:
		h := sha512.New384()
		h.Write(publicArea)
		hash = h.Sum(nil)
	case tpm2.TPMAlgSHA512:
		h := sha512.New()
		h.Write(publicArea)
		hash = h.Sum(nil)
	default:
		return nil, fmt.Errorf("unsupported algorithm ID: %d", algID)
	}

	name := make([]byte, 2+len(hash)) // 2 bytes for Algorithm ID + hash length
	binary.BigEndian.PutUint16(name, uint16(algID))
	copy(name[2:], hash) // Copy the hash into the name after the Algorithm ID

	return name, nil
}
