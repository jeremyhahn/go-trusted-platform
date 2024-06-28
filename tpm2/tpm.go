package tpm2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/op/go-logging"
)

const (
	manufacturerIntel     = "Intel"
	intelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
	infoOpeningSimulator  = "tpm: opening TPM simulator connection"
	infoOpeningDevice     = "tpm: opening TPM 2.0 connection"
	infoClosingConnection = "tpm: closing connection"

	blobStorePrefix = "tpm"
)

var (
	EKCertIndex = tpm2.TPMHandle(0x01C00002) //  TCG specified location for RSA-EK-certificate

	ErrEndorsementCertNotFound     = errors.New("tpm: endorsement key certificate not found")
	ErrEndorsementKeyNotFound      = errors.New("tpm: endorsement key not found")
	ErrEKCertNotFound              = errors.New("tpm: endorsement key certificate not found")
	ErrInvalidEKCertFormat         = errors.New("tpm: invalid endorsement certificate format")
	ErrInvalidEKCert               = errors.New("tpm: failed to verify endorsement key certificate")
	ErrDeviceAlreadyOpen           = errors.New("tpm: device already open")
	ErrOpeningDevice               = errors.New("tpm: error opening device")
	ErrInvalidSessionType          = errors.New("tpm: invalid session type")
	ErrInvalidSRKAuth              = errors.New("tpm: invalid storage root key auth")
	ErrInvalidActivationCredential = errors.New("tpm: invalid activation credential")
	ErrHashAlgorithmNotSupported   = errors.New("tpm: hash algorithm not supported")
	ErrInvalidPolicyDigest         = errors.New("tpm: invalid policy digest")
	ErrInvalidHandle               = errors.New("tpm: invalid entity handle")
	ErrUnexpectedRandomBytes       = errors.New("verifier: unexpected number of random bytes read")
)

type TrustedPlatformModule2 interface {
	DebugPrimaryKey(key Key)
	DebugAttestationKey(ak DerivedKey)
	Random() ([]byte, error)
	ImportTSSFile(ekCertPath string, verify bool) (*x509.Certificate, error)
	ImportEK(domain, cn string, ekCert *x509.Certificate, verify bool) (*x509.Certificate, error)
	ImportDER(domain, cn string, ekDER []byte, verify bool) (*x509.Certificate, error)
	ImportPEM(domain, cn string, ekCertPEM []byte, verify bool) (*x509.Certificate, error)
	HMACAuthSessionWithKey(srk Key, password []byte) (s tpm2.Session, close func() error, err error)
	HMACAuthSession(srkAuth []byte) (s tpm2.Session, close func() error, err error)
	SaltedHMACSession(Key) tpm2.Session
	HMACSession() tpm2.Session
	Unseal(srk Key, createResponse *tpm2.CreateResponse, sealName, sealAuth []byte) ([]byte, error)
	Seal(srk Key, sealAuth, sealName, sealData []byte) (*tpm2.CreateResponse, error)
	ECCSRK(ek Key, password []byte) (Key, error)
	RSASRK(ek Key, password []byte) (Key, error)
	CreateAK(srk Key) (*tpm2.CreateResponse, error)
	RSAEK() (Key, error)
	ECCEK() (Key, error)
	EKCert(ekHandle *tpm2.TPMHandle, srkAuth []byte) (*x509.Certificate, error)
	Capabilities() (tpm20Info, error)
	Init() error
	EKRSAPubKey() *rsa.PublicKey
	SetCertificateAuthority(ca ca.CertificateAuthority)
	Close() error
	Flush(handle tpm2.TPMHandle)
	ReadPCRs() (map[string][][]byte, error)
	ActivateCredential(ak DerivedKey, credential Credential) ([]byte, error)
	MakeCredential(ek Key, ak DerivedKey, secret []byte) (*tpm2.MakeCredentialResponse, []byte, error)
	RSAAK() (Key, DerivedKey, error)
	Encode(bytes []byte) string
	Decode(s string) ([]byte, error)
	// MeasurementLog() (*EventLog, error)
	Measurements(logpath []byte) (*EventLog, error)
	ParseEKCertificate(ekCert []byte) (*x509.Certificate, error)
	Open() error
	RandomReader() io.Reader
	Quote(pcrs []uint, nonce []byte) (Quote, error)
}

type TPM2 struct {
	logger       *logging.Logger
	debugSecrets bool
	domain       string
	config       *Config
	device       *os.File
	ca           ca.CertificateAuthority
	ekRSAPubKey  *rsa.PublicKey
	ekECCPubKey  *ecdh.PublicKey
	ekCertName   string
	ekBlobKey    string
	random       io.Reader
	// ekECCPubKey *ecdsa.PublicKey
	transport transport.TPM
	simulator *simulator.Simulator
	// TODO: Replace this with opaque key
	caPassword []byte
	TrustedPlatformModule2
}

// Creates a new TPM2 instance and opens a socket to a
// Trusted Platform Module (TPM). When this function
// returns the TPM is ready for use.
func NewTPM2(
	logger *logging.Logger,
	debugSecrets bool,
	config *Config,
	caPassword []byte,
	domain string) (TrustedPlatformModule2, error) {

	if config == nil || config.Device == "" {
		config.Device = "/dev/tpmrm0"
	}

	logger.Infof("%s %s", infoOpeningDevice, config.Device)

	f, err := os.OpenFile(config.Device, os.O_RDWR, 0)
	if err != nil {
		logger.Error(err)
		return nil, ErrOpeningDevice
	}

	ekCertName := fmt.Sprintf("%s-ek", domain)
	tpm := &TPM2{
		logger:       logger,
		debugSecrets: debugSecrets,
		config:       config,
		device:       f,
		transport:    transport.FromReadWriter(f),
		ekCertName:   ekCertName,
		ekBlobKey:    fmt.Sprintf("%s/%s/%s", blobStorePrefix, domain, ekCertName),
		domain:       domain,
		caPassword:   caPassword}

	random, err := tpm.randomReader()
	if err != nil {
		return nil, err
	}
	tpm.random = random
	return tpm, nil
}

// Creates a new Trusted Platoform Module Simulator (Software TPM)
func NewSimulation(
	logger *logging.Logger,
	debugSecrets bool,
	config *Config,
	caPassword []byte,
	domain string) (TrustedPlatformModule2, error) {

	logger.Info(infoOpeningSimulator)

	sim, err := simulator.Get()
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	ekCertName := fmt.Sprintf("%s-ek", domain)

	tpm := &TPM2{
		logger:       logger,
		config:       config,
		debugSecrets: debugSecrets,
		device:       nil,
		simulator:    sim,
		transport:    transport.FromReadWriter(sim),
		ekCertName:   ekCertName,
		ekBlobKey:    fmt.Sprintf("%s/%s/%s", blobStorePrefix, domain, ekCertName),
		domain:       domain,
		caPassword:   caPassword}

	random, err := tpm.randomReader()
	if err != nil {
		return nil, err
	}
	tpm.random = random
	return tpm, nil
}

// Re-opens a TPM connection
func (tpm *TPM2) Open() error {

	var t transport.TPM

	if tpm.config.UseSimulator && tpm.simulator == nil {

		tpm.logger.Info(infoOpeningSimulator)
		sim, err := simulator.Get()
		if err != nil {
			tpm.logger.Error(err)
			return err
		}
		tpm.simulator = sim
		t = transport.FromReadWriter(sim)
	} else {

		tpm.logger.Infof("%s %s", infoOpeningDevice, tpm.config.Device)
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

// Injects the Certificate Authority after instantiation
func (tpm *TPM2) SetCertificateAuthority(ca ca.CertificateAuthority) {
	tpm.ca = ca
}

// Returns a random source reader. If UseEntropy option is enabled
// in the TPM config, the TPM’s True Random Number Generator will be
// used, otherwise the runtime rand.Reader is used.
//
// https://github.com/tpm2dev/tpm.dev.tutorials/blob/master/Random_Number_Generator/README.md
func (tpm *TPM2) RandomReader() io.Reader {
	return tpm.random
}

// Returns the TPM Endorsement Key (EK) Public (Key
func (tpm *TPM2) EKRSAPubKey() *rsa.PublicKey {
	return tpm.ekRSAPubKey
}

// Returns the logical TPM transport connection
// func (tpm *TPM2) Transport() transport.TPM {
// 	return tpm.transport
// }

// Initializes the TPM device by loading an existing Endorsement Key and x509
// Certificate, and performing Local Attestation. If the Endorssement  Key (EK)
// doesn't exist in the CA, a new EK is created and imported into the
// CA, Local Attestation platform measurements are taken, sealed to TPM PCRs, and
// the EK public key, certificate and platform measurements are signed and
// saved to the CA's signed blob store.
func (tpm *TPM2) Init() error {

	tpm.logger.Info("Retrieving TPM Endorsement Key (EK) and Certificate from Certificate Authority")

	if _, err := tpm.EKCert(nil, nil); err != nil {
		return err
	}

	// if err := tpm.attestLocal(); err != nil {
	// 	return err
	// }

	return nil
}

// Returns a parsed TPM Event Log
func (tpm *TPM2) Measurements(logpath []byte) (*EventLog, error) {

	if logpath == nil {
		measurementLog, err := os.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
		if err != nil {
			tpm.logger.Error("tpm: error reading event log: %s", err)
			return nil, err
		}

		tpm.logger.Infof("tpm: read %d bytes from event log", len(measurementLog))

		return ParseEventLog(measurementLog)
	}

	tpm.logger.Infof("tpm: parsing event log: %+v", logpath)

	return ParseEventLog(logpath)
}

// Retrieve the requested Endorsement Key Certificate from the Certificate
// Authority signed blob store. If the certificate can not be found, treat
// this as an initial setup and try to load the cert from TPM NVRAM. If that
// fails, try to download the certificate from the Manufacturer's EK cert
// service. If that fails, try to load the certificate from the current
// working directory as a final attempt.
func (tpm *TPM2) EKCert(ekHandle *tpm2.TPMHandle, srkAuth []byte) (*x509.Certificate, error) {

	tpm.logger.Debug("tpm: checking Certificate Authority for signed EK certificate")

	// Check the CA for a signed EK cert
	certPEM, err := tpm.ca.SignedData(tpm.ekBlobKey)
	if err == nil {
		// Perform integrity check on the cert
		if err := tpm.ca.PersistentVerifySignature(tpm.ekBlobKey, certPEM); err != nil {
			return nil, err
		}
		tpm.logger.Info("tpm: loading EK certificate from Certificate Authority")
		// Decode and return the signed and verified x509 EK cert from the CA
		ekCert, err := tpm.ca.DecodePEM(certPEM)
		if err != nil {
			return nil, err
		}
		return ekCert, nil
	}
	if err != ca.ErrBlobNotFound {
		return nil, err
	}

	// No EK found in the CA. Treat this as an initial platform setup...

	// Create RSA EK
	ek, err := tpm.RSAEK()
	if err != nil {
		return nil, err
	}

	// Create RSA SRK
	srk, err := tpm.RSASRK(ek, srkAuth)
	if err != nil {
		return nil, err
	}

	// Create session to the TPM. Use SRK password auth if provided.
	var session tpm2.Session
	var closer func() error
	if srkAuth != nil {
		session, closer, err = tpm.HMACAuthSessionWithKey(srk, srkAuth)
		if err != nil {
			return nil, err
		}
		defer closer()
	} else {
		session = tpm.HMACSession()
	}

	// Attempt to read the cert from NVRAM
	response, err := tpm2.NVReadPublic{
		NVIndex: EKCertIndex,
	}.Execute(tpm.transport, session)
	if err != nil {
		tpm.logger.Error(err)

		// No EK cert found in NVRAM. Try downloading from the manufacturer EK certificate service
		manufacuterCert, err := tpm.downloadEKCertFromManufacturer()
		if err == nil && len(manufacuterCert) > 0 {
			return x509.ParseCertificate(manufacuterCert)
		}

		// Nope, final attempt: look for a raw TSS formatted certificate in the current working directory
		if _, err := os.Stat(tpm.config.EKCert); errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return tpm.ImportTSSFile(tpm.config.EKCert, true)

	} else {
		certPEM = response.NVPublic.Bytes()
	}

	// Make sure the certificate is a valid x509 cert
	cert, err := x509.ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	// Import the EK public key to the CA
	tpm.logger.Infof("tpm: importing EK Public Key to Certificate Authority")
	if err := tpm.ca.ImportPubKey(tpm.ekCertName, cert.PublicKey); err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Sign and save the EK certificate to the CA
	tpm.logger.Infof("tpm: signing EK certificate and importing to Certificate Authority")
	if err := tpm.ca.PersistentSign(tpm.ekCertName, certPEM, tpm.caPassword, true); err != nil {
		return nil, err
	}

	return cert, nil
}

// Returns an Elliptical Curve Cryptography (ECC) Endorsement Key (EK) in alignment
// with the TCG reference ECC-P256 EK template.
func (tpm *TPM2) ECCEK() (Key, error) {

	tpm.logger.Debug("tpm: creating ECC Endorsement Key (EK)")

	ekCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}
	response, err := ekCreate.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	//defer tpm.Flush(response.ObjectHandle)

	key, err := tpm.parsePrimaryECC(response)
	if err != nil {
		return key, err
	}
	key.BPublicBytes = response.OutPublic.Bytes()
	tpm.ekECCPubKey = key.ECCPubKey
	return key, nil
}

// Creates an Rivest Shamir Adleman (RSA) Endorsement Key (EK) in alignment with
// the TCG reference RSA-2048 EK template.
func (tpm *TPM2) RSAEK() (Key, error) {

	tpm.logger.Debug("tpm: creating RSA Endorsement Key (EK)")

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}

	response, err := createPrimary.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	//defer tpm.Flush(response.ObjectHandle)

	key, err := tpm.parsePrimaryRSA(response)
	if err != nil {
		return key, nil
	}
	key.BPublicBytes = response.OutPublic.Bytes()
	tpm.ekRSAPubKey = key.RSAPubKey
	return key, nil
}

// Create new ECC Storage Root Key (SRK). Returns the SRK handle to be used
// in subsequent calls / operations and requires a call to Flush when done.
// NOTE: TCG spec disallows sealing to endorsement keys
func (tpm *TPM2) ECCSRK(ek Key, password []byte) (Key, error) {

	tpm.logger.Debug("tpm: creating new Storage Root Key (SRK)")

	createPrimaryCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	if len(password) > 0 {
		createPrimaryCMD.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: password,
				},
			},
		}
	}

	// Execute the create SRK command
	var response *tpm2.CreatePrimaryResponse
	var err error
	if tpm.config.EncryptSession {
		response, err = createPrimaryCMD.Execute(
			tpm.transport,
			tpm.SaltedHMACSession(ek))
	} else {
		response, err = createPrimaryCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	//defer tpm.Flush(srk.ObjectHandle)

	// saveContextCMD := tpm2.ContextSave{
	// 	SaveHandle: srk.ObjectHandle,
	// }
	// saveContextResponse, err := saveContextCMD.Execute(tpm.transport)
	// if err != nil {
	// 	return key, err
	// }
	// saveContextResponse.Context

	key, err := tpm.parsePrimaryECC(response)
	if err != nil {
		return Key{}, nil
	}
	key.BPublicBytes = response.OutPublic.Bytes()

	tpm.logger.Debugf("tpm: created ECC Storage Root Key (SRK) with handle: 0x%x",
		response.ObjectHandle)

	return key, nil
}

// Create RSA Storage Root Key (SRK). Returns the SRK handle to be used
// in subsequent calls / operations and requires a call to Flush when done.
// NOTE: TCG spec disallows sealing to endorsement keys
func (tpm *TPM2) RSASRK(ek Key, password []byte) (Key, error) {

	tpm.logger.Debug("tpm: creating new RSA Storage Root Key (SRK)")

	var err error
	var response *tpm2.CreatePrimaryResponse

	createPrimaryCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}
	if len(password) > 0 {
		createPrimaryCMD.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: password,
				},
			},
		}
	}
	if tpm.config.EncryptSession {
		response, err = createPrimaryCMD.Execute(
			tpm.transport,
			tpm.SaltedHMACSession(ek))
	} else {
		response, err = createPrimaryCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	//defer tpm.Flush(srk.ObjectHandle)

	key, err := tpm.parsePrimaryRSA(response)
	if err != nil {
		return Key{}, nil
	}
	key.BPublicBytes = response.OutPublic.Bytes()
	key.Auth = password

	tpm.logger.Debugf("tpm: created RSA Storage Root Key (SRK) with handle: 0x%x",
		response.ObjectHandle)

	return key, nil
}

// Create an Eliptical Curve Cryptography (ECC) Attestation Key
func (tpm *TPM2) ECCAK() (Key, DerivedKey, error) {

	tpm.logger.Info("Creating Eliptical Curve Cryptography (ECC) Endorsement Key (EK)")

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	ek, err := tpm.parsePrimaryRSA(primaryKey)
	if err != nil {
		return Key{}, DerivedKey{}, nil
	}
	tpm.logger.Debugf("tpm: created Endorsement Key (EK): %s", tpm.Encode(ek.Name.Buffer))

	// Create a stateful policy based session that uses a TPM generated one-time
	// use nonce that is sent with each command performed in the session, to prevent
	// replay attacks.
	tpm.logger.Debug("tpm: creating TPM PolicySession")
	session, closer, err := tpm2.PolicySession(tpm.transport, tpm2.TPMAlgSHA256, 16)
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error(err)
		}
	}()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}

	tpm.logger.Debug("tpm: Setting session policy")
	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}

	// Verify the policy digest to ensure the policy
	// criteria was met using a trial session. A trial
	// session
	trialSession, closer, err := tpm2.PolicySession(
		tpm.transport, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error(err)
		}
	}()
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}

	tpm.logger.Debug("tpm: loading EK using policy based session")

	// Apply the policy digest to the AK

	// Create a new SRK template, setting the policy digest
	akWithAuthTemplate := tpm2.RSASRKTemplate
	akWithAuthTemplate.AuthPolicy = pgd.PolicyDigest
	// Create the key using the rsaSRKTemplate w/ AuthPolicy
	createLoadedResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   session,
		},
		InPublic: tpm2.New2BTemplate(&akWithAuthTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	defer tpm.Flush(createLoadedResponse.ObjectHandle)

	// Retrieve the public area of the loaded object
	akPub, err := createLoadedResponse.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	// Parse the RSA public / private key
	akECC, err := tpm.parseECC(akPub, createLoadedResponse.OutPrivate.Buffer)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}

	ak := DerivedKey{
		CreationHash:   primaryKey.CreationHash.Buffer,
		CreationData:   primaryKey.CreationData.Bytes(),
		CreationTicket: primaryKey.CreationTicket.Digest.Buffer,
	}
	ak.Handle = createLoadedResponse.ObjectHandle
	ak.Public = akECC.Public
	ak.Name = createLoadedResponse.Name.Buffer
	ak.BPublicBytes = createLoadedResponse.OutPublic.Bytes()
	ak.RSAPubKey = akECC.RSAPubKey
	ak.PublicKeyBytes = akECC.PublicKeyBytes
	ak.PublicKeyPEM = akECC.PublicKeyPEM
	ak.PrivateKeyBytes = akECC.PrivateKeyBytes

	return ek, ak, nil
}

// Creates a new key under the hierarchy of the specified key parameter.
// For example, pass a Storage Root Key as the key parameter to generate
// a new key under the storage hierarchy.
func (tpm *TPM2) DerivedKey(key Key) (Key, error) {

	tpm.logger.Debug("tpm: creating new RSA key from parent key: %x", tpm.Encode(key.Name.Buffer))

	var err error
	session, closer, err := tpm.HMACAuthSessionWithKey(key, key.Auth)
	defer closer()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}

	createKeyCMD := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: key.Handle,
			Name:   key.Name,
			Auth:   session,
		},
		InPublic: tpm2.New2B(rsaTemplate),
		// CreationPCR: tpm2.TPMLPCRSelection{
		// 	PCRSelections: []tpm2.TPMSPCRSelection{
		// 		{
		// 			Hash:      tpm2.TPMAlgSHA256,
		// 			PCRSelect: tpm2.PCClientCompatible.PCRs(debugPCR),
		// 		},
		// 	},
		// },
		// InSensitive: tpm2.TPM2BSensitiveCreate{
		// 	Sensitive: &tpm2.TPMSSensitiveCreate{
		// 		UserAuth: tpm2.TPM2BAuth{
		// 			Buffer: sealAuth,
		// 		},
		// 		Data: tpm2.NewTPMUSensitiveCreate(
		// 			&tpm2.TPM2BSensitiveData{
		// 				Buffer: sealData,
		// 			}),
		// 	},
		// },
	}

	var createKeyResponse *tpm2.CreateResponse
	if tpm.config.EncryptSession {
		createKeyResponse, err = createKeyCMD.Execute(
			tpm.transport,
			tpm.SaltedHMACSession(key))
	} else {
		createKeyResponse, err = createKeyCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}

	pub, err := createKeyResponse.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}

	derivedKey := Key{}
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsa, err := tpm.parseRSA(pub, nil)
		if err != nil {
			return Key{}, err
		}
		derivedKey.RSAPubKey = rsa.RSAPubKey

	case tpm2.TPMAlgECC:
		ecc, err := tpm.parseECC(pub, nil)
		if err != nil {
			return Key{}, err
		}
		derivedKey.ECCPubKey = ecc.ECCPubKey
	}

	return derivedKey, nil
}

// Creates a new RSA Attestation Key and policy session to restricting the key
// usage to the session.
func (tpm *TPM2) RSAAK() (Key, DerivedKey, error) {

	// Not printing Rivest, Shamir, and Adleman here because its
	// a lot of bytes in the log and they need no introduction :)
	tpm.logger.Info("Creating RSA Endorsement Key (EK)")

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	ek, err := tpm.parsePrimaryRSA(primaryKey)
	if err != nil {
		return Key{}, DerivedKey{}, nil
	}

	tpm.logger.Debugf("tpm: created Endorsement Key (EK): %s", tpm.Encode(ek.Name.Buffer))

	// Create a stateful policy based session that uses a TPM generated one-time
	// use nonce that is sent with each command performed in the session, to prevent
	// replay attacks.
	tpm.logger.Debug("tpm: creating TPM PolicySession")
	session, closer, err := tpm2.PolicySession(tpm.transport, tpm2.TPMAlgSHA256, 16)
	// TPM_RC_HANDLE (parameter 1): the handle is not correct for the use
	// defer func() {
	// 	if err := closer(); err != nil {
	// 		tpm.logger.Error(err)
	// 	}
	// }()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}

	tpm.logger.Debug("tpm: Setting session policy")
	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}

	// "During a trial policy session, all assertions pass; the purpose
	// of the trial policy session is to generate the policyDigest as
	// if all the assertions passed. After all the policy commands are
	// sent to the TPM, the policyDigest can be read from the TPM using
	// the TPM2_GetPolicyDigest command."
	//
	// See "Policy Authorization Time Intervals" for details:
	// https://link.springer.com/chapter/10.1007/978-1-4302-6584-9_13
	trialSession, closer, err := tpm2.PolicySession(
		tpm.transport, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error(err)
		}
	}()
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}

	tpm.logger.Debug("tpm: loading EK using policy based session")

	// Create the AK using the HMAC session with an authorization
	// policy that restricts the key usage to this session.

	// Use the SRK template, setting the policy digest
	akWithAuthTemplate := tpm2.RSASRKTemplate
	akWithAuthTemplate.AuthPolicy = pgd.PolicyDigest

	// Create the key using the tpm2.RSAEKTemplate w/ AuthPolicy
	createLoadedResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   session,
		},
		InPublic: tpm2.New2BTemplate(&akWithAuthTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	defer tpm.Flush(createLoadedResponse.ObjectHandle)

	// Retrieve the public area of the loaded object
	akPub, err := createLoadedResponse.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	// Parse the key from the public area
	akRSA, err := tpm.parseRSA(akPub, createLoadedResponse.OutPrivate.Buffer)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, DerivedKey{}, nil
	}
	ak := DerivedKey{
		CreationHash:   primaryKey.CreationHash.Buffer,
		CreationData:   primaryKey.CreationData.Bytes(),
		CreationTicket: primaryKey.CreationTicket.Digest.Buffer,
	}
	ak.Handle = createLoadedResponse.ObjectHandle
	ak.Public = akRSA.Public
	ak.Name = createLoadedResponse.Name.Buffer
	ak.BPublicBytes = createLoadedResponse.OutPublic.Bytes()
	ak.RSAPubKey = akRSA.RSAPubKey
	ak.PublicKeyBytes = akRSA.PublicKeyBytes
	ak.PublicKeyPEM = akRSA.PublicKeyPEM
	ak.PrivateKeyBytes = akRSA.PrivateKeyBytes

	tpm.DebugPrimaryKey(ek)
	tpm.DebugAttestationKey(ak)

	return ek, ak, nil
}

// Performs TPM2_MakeCredential, returning the new credential
// challenge for a remote Attestor. If the secret parameter is
// not provided, a random secret will be generated. If the
// "entropy" TPM option is enabled, the TPM RNG will be used
// to generate the secret, otherwise the runtime / operating
// system generator will be used.
func (tpm *TPM2) MakeCredential(ek Key, ak DerivedKey, secret []byte) (*tpm2.MakeCredentialResponse, []byte, error) {

	tpm.logger.Info("Creating new Activation Credential")

	if secret == nil {
		var err error
		secret, err = tpm.Random()
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf(
			"tpm: MakeCredential secret (raw): %s", secret)
		tpm.logger.Debugf(
			"tpm: MakeCredential secret (hex): 0x%x", tpm.Encode(secret))
	}

	digest := tpm2.TPM2BDigest{Buffer: secret}

	// Load the Endorsement Key (EK)
	loadedEK, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](ek.BPublicBytes),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, err
	}
	defer tpm.Flush(loadedEK.ObjectHandle)
	tpm.logger.Debugf("tpm: loaded EK name: 0x%x", tpm.Encode(loadedEK.Name.Buffer))

	// Load the Attestation Key (AK)
	loadedKey, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](ak.BPublicBytes),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, err
	}
	defer tpm.Flush(loadedKey.ObjectHandle)
	tpm.logger.Debugf("tpm: loaded AK name: 0x%x", tpm.Encode(loadedKey.Name.Buffer))

	// Create the new credential challenge
	mc, err := tpm2.MakeCredential{
		Handle:      loadedEK.ObjectHandle,
		Credential:  digest,
		ObjectNamae: loadedKey.Name,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, err
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: MakeCredential: secret (raw): %s", digest.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: secret (hex): 0x%x", tpm.Encode(digest.Buffer))

		tpm.logger.Debugf("tpm: MakeCredential: encrypted secret (raw): %s", mc.CredentialBlob.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: encrypted secret (hex): 0x%x", tpm.Encode(mc.CredentialBlob.Buffer))

		tpm.logger.Debugf("tpm: MakeCredential: secret response (raw): %s", mc.Secret.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: secret response (hex): 0x%x", tpm.Encode(mc.Secret.Buffer))
	}

	return mc, digest.Buffer, nil
}

// Activates a credential challenge previously initiated by MakeCredential
func (tpm *TPM2) ActivateCredential(ak DerivedKey, credential Credential) ([]byte, error) {

	tpm.logger.Info("Activating Credential")

	// Create Endorsement Key (EK)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	// Load Attestation Key (AK)
	loadedAK, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, tpm.ekPolicy),
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](ak.BPublicBytes),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: ak.PrivateKeyBytes,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	tpm.logger.Debugf("tpm2: loaded AK: %x", tpm.Encode(loadedAK.Name.Buffer))

	// Create a new policy session to authenticate the ActivateCredential command,
	// ensuring only the session that created the AK can perform the activation.
	tpm.logger.Debug("tpm2: creating policy session")
	session, closer, err := tpm2.PolicySession(tpm.transport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error(err)
		}
	}()

	// Couple the ActivateCredential authorization with the session
	tpm.logger.Debug("tpm2: satisfying policy criteria")
	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Activate the credential, proving the AK and EK are both loaded
	// into the same TPM, and the EK is able to decrypt the secret.
	tpm.logger.Debug("tpm2: activating credential")
	activateCredentialsResponse, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: loadedAK.ObjectHandle,
			Name:   loadedAK.Name,
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   session,
		},
		CredentialBlob: tpm2.TPM2BIDObject{
			Buffer: credential.CredentialBlob,
		},
		Secret: tpm2.TPM2BEncryptedSecret{
			Buffer: credential.EncryptedSecret,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, ErrInvalidActivationCredential
	}

	// Release the decrypted secret. Print some helpful info
	// if secret debugging is enabled.
	digest := activateCredentialsResponse.CertInfo.Buffer
	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: credential encrypted secret (raw): %s", credential.EncryptedSecret)
		tpm.logger.Debugf("tpm: credential encrypted secret (hex): 0x%x", tpm.Encode(credential.EncryptedSecret))

		tpm.logger.Debugf("tpm: TPM2BDigest (raw): %s", digest)
		tpm.logger.Debugf("tpm: TPM2BDigest (hex): 0x%x", tpm.Encode(digest))
	}

	// Return the decrypted secret
	return digest, nil
}

// Creates a Quote signed by the Endorsement Key
func (tpm *TPM2) Quote(pcrs []uint, nonce []byte) (Quote, error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Quote{}, err
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			STClear:             false,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	}

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Quote{}, err
	}
	defer tpm.Flush(rsaKeyResponse.ObjectHandle)

	// Create PCR selection(s)
	pcrSelections := make([]tpm2.TPMSPCRSelection, len(pcrs))
	for i, pcr := range pcrs {
		pcrSelections[i] = tpm2.TPMSPCRSelection{

			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
		}
	}
	pcrSelect := tpm2.TPMLPCRSelection{
		PCRSelections: pcrSelections,
	}

	// Create the quote
	q, err := tpm2.Quote{
		SignHandle: rsaKeyResponse.ObjectHandle,
		QualifyingData: tpm2.TPM2BData{
			Buffer: nonce,
		},
		PCRSelect: pcrSelect,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return Quote{}, err
	}

	// rsassa, err := q.Signature.Signature.RSASSA()
	// if err != nil {
	// 	tpm.logger.Error(err)
	// 	return Quote{}, err
	// }

	return Quote{
		Quoted: q.Quoted.Bytes(),
		Nonce:  nonce,
	}, nil
}

// Decrypts an encrypted blob using the requested Attestation Key (AK)
// pointed to by akHandle.
func (tpm *TPM2) RSADecrypt(
	akHandle tpm2.TPMHandle,
	blob []byte) ([]byte, error) {

	response, err := tpm2.RSADecrypt{
		KeyHandle:  akHandle,
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: blob},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return response.Message.Buffer, nil
}

// Encrypts the message using the requested Attestation Key (AK)
// pointed to by akHandle.
func (tpm *TPM2) RSAEncrypt(
	akHandle tpm2.TPMHandle,
	message []byte) ([]byte, error) {

	response, err := tpm2.RSAEncrypt{
		KeyHandle: akHandle,
		Message:   tpm2.TPM2BPublicKeyRSA{Buffer: message},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return response.OutData.Buffer, nil
}

// Creates a new Attestment Key
func (tpm *TPM2) Seal(
	derived Key, sealAuth, sealName, sealData []byte) (*tpm2.CreateResponse, error) {

	tpm.logger.Debugf("tpm: sealing %s with parent key handle 0x%x", sealName, derived.Handle)
	if tpm.debugSecrets {

		tpm.logger.Debugf("tpm: SRK auth: %s", derived.Auth)

		tpm.logger.Debugf("tpm: seal secret (raw): %+v", sealAuth)
		tpm.logger.Debugf("tpm: seal secret (hex): 0x%x", tpm.Encode(sealAuth))
		tpm.logger.Debugf("tpm: seal secret (string): %s", string(sealAuth))

		tpm.logger.Debugf("tpm: seal data (raw): %+v", sealData)
		tpm.logger.Debugf("tpm: seal data (hex): 0x%x", tpm.Encode(sealData))
		tpm.logger.Debugf("tpm: seal data (string): %s", string(sealData))
	}

	tpm.logger.Debugf("tpm: creating seal session: %+v", sealAuth)
	session, closer, err := tpm.HMACAuthSessionWithKey(derived, derived.Auth)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer()

	createBlobCMD := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: derived.Handle,
			Name:   derived.Name,
			Auth:   session,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: sealAuth,
				},
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{
						Buffer: sealData,
					}),
			},
		},
	}
	createBlobResponse, err := createBlobCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	tpm.logger.Debugf("tpm: sealed %s to TPM", string(sealName))

	return createBlobResponse, nil
}

// Unseals data stored in the TPM under the Storage Root Key (SRK)
func (tpm *TPM2) Unseal(
	srk Key,
	createResponse *tpm2.CreateResponse,
	sealName, sealAuth []byte) ([]byte, error) {

	tpm.logger.Debugf("tpm: unsealing %s", string(sealName))
	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: seal secret (raw): %+v", sealAuth)
		tpm.logger.Debugf("tpm: seal secret (hex): 0x%x", tpm.Encode(sealAuth))
		tpm.logger.Debugf("tpm: seal secret (string): %s", string(sealAuth))
	}

	// Create authenticated session using SRK
	var session tpm2.Session
	var closer func() error
	session, closer, err := tpm.HMACAuthSessionWithKey(srk, srk.Auth)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer()

	// Load the sealed blob
	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.Handle,
			Name:   srk.Name,
			Auth:   session,
		},
		InPrivate: createResponse.OutPrivate,
		InPublic:  createResponse.OutPublic,
	}
	loadResponse, err := loadBlobCmd.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer tpm.Flush(loadResponse.ObjectHandle)

	// Create a new session using the Seal auth
	if tpm.config.EncryptSession {
		session, closer, err = tpm.HMACAuthSessionWithKey(srk, sealAuth)
	} else {
		session, closer, err = tpm.HMACAuthSession(sealAuth)
	}
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer()

	// Unseal the blob
	unsealResponse, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   loadResponse.Name,
			Auth:   session,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	tpm.logger.Debugf("tpm: successfully unsealed %s", string(sealName))

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: unsealed (raw) %+v", unsealResponse.OutData.Buffer)
		tpm.logger.Debugf("tpm: unsealed (hex) 0x%x", tpm.Encode(unsealResponse.OutData.Buffer))
		tpm.logger.Debugf("tpm: unsealed (string) %s", string(unsealResponse.OutData.Buffer))
	}

	return unsealResponse.OutData.Buffer, nil
}

// Creates a "one-time", unauthenticated, NON-encrypted HMAC session to the TPM
func (tpm *TPM2) HMACSession() tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16,
		tpm2.AESEncryption(128, tpm2.EncryptInOut))
}

// Creates a new HMAC session with the TPM
func (tpm *TPM2) HMACAuthSession(srkAuth []byte) (s tpm2.Session, close func() error, err error) {
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		// Auth uses the session to prove knowledge of the object's auth value.
		tpm2.Auth(srkAuth),
		tpm2.AESEncryption(
			128,
			tpm2.EncryptOut))
}

// Creates a new authenticated, salted HMAC session. If session encryption is enabled, the
// session is salted using the derived tpm2.TPMTPublic key.
func (tpm *TPM2) HMACAuthSessionWithKey(derived Key, auth []byte) (s tpm2.Session, close func() error, err error) {
	if tpm.config.EncryptSession {
		tpm.logger.Debugf("tpm: created encrypted HMAC session using key handle: 0x%x", derived.Handle)
		return tpm2.HMACSession(
			tpm.transport,
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(auth),
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut),
			tpm2.Salted(derived.Handle, derived.Public))
	}
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Auth(auth),
		tpm2.AESEncryption(
			128,
			tpm2.EncryptInOut))
}

// Creates an unauthenticated, encrypted HMAC session with the TPM. Bus communication
// between the CPU <-> TPM is secured using a salted session from the derived key.
func (tpm *TPM2) SaltedHMACSession(derived Key) tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16,
		// AESEncryption uses the session to encrypt the first parameter sent to/from
		// the TPM.
		// Note that only commands whose first command/response parameter is a 2B can
		// support session encryption.
		// EncryptIn specifies a decrypt session.
		// EncryptOut specifies an encrypt session.
		// EncryptInOut specifies a decrypt+encrypt session
		tpm2.AESEncryption(
			128,
			tpm2.EncryptInOut),
		// Salted specifies that this session's session key should depend on an
		// encrypted seed value using the given public key.
		// 'handle' must refer to a loaded RSA or ECC key.
		tpm2.Salted(derived.Handle, derived.Public))
}

// Returns a random reader that reads random bytes to produce entropy during
// private key operations. If UseEntropy is disabled in the config, the default
// runtime random reader is used instead of the TPM. If session encryption is
// enabled, communication bus between CPU <-> TPM bus will be encrypted using
// a salted HMAC session.
func (tpm *TPM2) randomReader() (io.Reader, error) {

	// Use golang runtime random entropy if
	// TPM entropy isn't enabled
	if !tpm.config.UseEntropy {
		tpm.logger.Info("tpm: entropy source: runtime")
		return rand.Reader, nil
	}

	tpm.logger.Info("tpm: entropy source: TPM")

	// Create a new TPM transport and random reader
	reader := NewRandomReader(tpm.transport)
	if tpm.config.EncryptSession {

		tpm.logger.Info("tpm: encrypting TPM <-> CPU entropy communication")

		response, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		}.Execute(tpm.transport)
		defer tpm.Flush(response.ObjectHandle)

		ekPub, err := response.OutPublic.Contents()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		reader.EncryptionHandle = response.ObjectHandle
		reader.EncryptionPub = ekPub
	}
	return reader, nil
}

// Generates a random 32 byte fixed length []byte
func (tpm *TPM2) Random() ([]byte, error) {

	var err error
	var n int
	fixedLength := 32
	bytes := make([]byte, fixedLength)

	// Read fixed length bytes
	n, err = tpm.RandomReader().Read(bytes)
	if n != fixedLength {
		return nil, ErrUnexpectedRandomBytes
	}
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	tpm.logger.Debugf("tpm: read %d random bytes", n)

	return bytes, nil
}

// Imports a local EK certificat in raw TCG Software Stack (TSS) form
// from a local disk.
func (tpm *TPM2) ImportTSSFile(
	ekCertPath string,
	verify bool) (*x509.Certificate, error) {

	var ekCert *x509.Certificate

	tpm.logger.Infof(
		"Attemping to load Endorsement Key (EK) Certificate from local disk: %s",
		ekCertPath)

	bytes, err := os.ReadFile(ekCertPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrEKCertNotFound
		}
		return nil, err
	}

	// Try parseing as ASN.1 DER form
	ekCert, err = x509.ParseCertificate(bytes)
	if err != nil {

		// Failed, try parsing PEM form
		ekCert, err = tpm.ca.DecodePEM(bytes)
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		return tpm.ImportEK(tpm.domain, tpm.ekCertName, ekCert, verify)
	}

	// Passed, encode the ASN.1 DER bytes to PEM
	// ekPEM, err := tpm.ca.EncodePEM(bytes)
	// if err != nil {
	// 	tpm.logger.Error(err)
	// 	return nil, err
	// }
	return tpm.ImportEK(tpm.domain, tpm.ekCertName, ekCert, verify)
}

// Imports a local or remote attestor EK certificate in raw ASN.1 DER form
func (tpm *TPM2) ImportDER(
	domain, cn string,
	ekDER []byte,
	verify bool) (*x509.Certificate, error) {

	tpm.logger.Info("Importing Endorsement Key (EK) Certificate in ASN.1 DER form")
	ekCert, err := x509.ParseCertificate(ekDER)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return tpm.ImportEK(domain, cn, ekCert, verify)
}

// Imports a local or remote attestor EK certificate in PEM form
func (tpm *TPM2) ImportPEM(
	domain, cn string,
	ekPEM []byte,
	verify bool) (*x509.Certificate, error) {

	tpm.logger.Info("Importing Endorsement Key (EK) Certificate in PEM form")
	var block *pem.Block
	if block, _ = pem.Decode(ekPEM); block == nil {
		return nil, ca.ErrInvalidEncodingPEM
	}
	ekCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return tpm.ImportEK(domain, cn, ekCert, verify)
}

// Imports a local or remote attestor x509 EK certificate
func (tpm *TPM2) ImportEK(
	domain, cn string,
	ekCert *x509.Certificate,
	verify bool) (*x509.Certificate, error) {

	tpm.logger.Infof("Importing %s x509 Endorsement Key (EK) Certificate", domain)

	// Convert the ASN.1 DER encoded certificate to PEM form
	ekCertPEM, err := tpm.ca.EncodePEM(ekCert.Raw)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Unhandled critical extensions cause Verify to fail
	for _, uce := range ekCert.UnhandledCriticalExtensions {
		tpm.logger.Warningf("tpm: EK certificate contains unhandled critical extention: %s",
			uce.String())
	}
	ekCert.UnhandledCriticalExtensions = nil

	// Verify the certificate using the Certificate Authority Root & Intermediate
	// Certifiates along with all imported Trusted Root and Intermediate certificates.
	if verify {
		_, err := tpm.ca.Verify(ekCert, &tpm.ekCertName)
		if err != nil {
			// The above Verify call should have already auto-imported
			// the issuing CA if auto-import is enabled for the CA. Now
			// check the TPM auto-import option to see if it overrides
			// the global CA setting to allow auto-importing EK platform
			// certs.
			if _, ok := err.(x509.UnknownAuthorityError); ok {
				// Auto-import the EK platform certificates
				// if auto-import-ek-certs enabled in the TPM
				// config section, overriding the CA global
				// auto-import setting.
				if tpm.config.AutoImportEKCerts {
					tpm.logger.Info("Importing Endorsement Key (EK) platform certificates")
					if err := tpm.ca.ImportIssuingCAs(ekCert, &tpm.ekCertName, ekCert); err != nil {
						return nil, err
					}
				}
			} else {
				return nil, err
			}
		}
		// All EK platform certs are imported into the Certificate
		// Authority trust store, now verify the EK certificate.
		valid, err := tpm.ca.Verify(ekCert, &tpm.ekCertName) // &tpm.ekCertName
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		if !valid {
			return nil, ca.ErrCertInvalid
		}
		tpm.logger.Debugf("tpm: successfully verified endorsement key certificate: %s", domain)
	}

	// Sign and save the EK cert to the CA's signed blob storage
	ekBlobKey := tpm.createEKCertBlobKey(domain, cn)
	if err := tpm.ca.PersistentSign(ekBlobKey, ekCertPEM, tpm.caPassword, true); err != nil {
		return nil, err
	}

	tpm.logger.Info("Endorsement Key (EK) successfully imported to Certificate Authority")

	return ekCert, nil
}

// Reads all Platform Configuration Register (PCR) values
func (tpm *TPM2) ReadPCRs() (map[string][][]byte, error) {

	maxPCR := uint(23)
	out := make(map[string][][]byte, 0)

	algoNames := []string{
		"SHA1",
		"SHA256",
		"SHA386",
		"SHA512"}

	algos := []tpm2.TPMAlgID{
		tpm2.TPMAlgSHA1,
		tpm2.TPMAlgSHA256,
		tpm2.TPMAlgSHA384,
		tpm2.TPMAlgSHA512}

	for j, algo := range algos {

		pcrs := make([][]byte, maxPCR+1)

		for i := uint(0); i < maxPCR+1; i++ {

			pcrRead := tpm2.PCRRead{
				PCRSelectionIn: tpm2.TPMLPCRSelection{
					PCRSelections: []tpm2.TPMSPCRSelection{
						{
							Hash:      algo,
							PCRSelect: PCClientCompatible.PCRs(uint(i)),
						},
					},
				},
			}

			pcrReadRsp, err := pcrRead.Execute(tpm.transport)
			if err != nil {
				if strings.Contains(err.Error(), ErrHashAlgorithmNotSupported.Error()) {
					//tpm.logger.Warningf("tpm: error reading PCR Bank %s: %s", algoNames[i], err)
					return out, nil
				}
			}
			if pcrReadRsp == nil {
				tpm.logger.Errorf("tpm: error reading PCR bank %s: %s", algoNames[j], err)
				return out, nil
			}

			buffer := pcrReadRsp.PCRValues.Digests[0].Buffer
			encoded := tpm.Encode(buffer)

			pcrs[i] = []byte(encoded)
			// tpm.logger.Debugf("pcr %d: 0x%s", i, encoded)
		}

		out[algoNames[j]] = pcrs
	}

	return out, nil
}

// Returns the supported TPM capabilities
func (tpm *TPM2) Capabilities() (tpm20Info, error) {

	var vendorInfo string

	// The Vendor String is split up into 4 sections of 4 bytes,
	// for a maximum length of 16 octets of ASCII text. We iterate
	// through the 4 indexes to get all 16 bytes & construct vendorInfo.
	// See: TPM_PT_VENDOR_STRING_1 in TPM 2.0 Structures reference.
	// Thanks, Google: https://github.com/google/go-attestation/blob/master/attest/tpm.go#L173
	for i := 0; i < 4; i++ {

		capabilityCMD := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      tpmPtVendorString + uint32(i),
			PropertyCount: 1}

		response, err := capabilityCMD.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error(err)
			return tpm20Info{}, err
		}

		tpm.logger.Debugf("%+v", response)

		props, err := response.CapabilityData.Data.TPMProperties()
		if err != nil {
			tpm.logger.Error(err)
			return tpm20Info{}, nil
		}

		// Reconstruct the 4 ASCII octets from the uint32 value.
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, props.TPMProperty[0].Value)
		vendorInfo += string(b)
	}

	// Manufacturer
	manufacturerCMD := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtManufacturer,
		PropertyCount: 1}

	response, err := manufacturerCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return tpm20Info{}, err
	}

	manufacturer, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		tpm.logger.Error(err)
		return tpm20Info{}, err
	}

	// Firmware
	firmwareCMD := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtFwVersion1,
		PropertyCount: 1}

	response, err = firmwareCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return tpm20Info{}, err
	}

	firmware, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		tpm.logger.Error(err)
		return tpm20Info{}, err
	}

	var vendor TCGVendorID = TCGVendorID(manufacturer.TPMProperty[0].Value)
	fw := firmware.TPMProperty[0].Value

	tpm.logger.Debugf("vendorInfo: %+v", vendorInfo)
	tpm.logger.Debugf("response: %+v", response)
	tpm.logger.Debugf("data: %+v", response.CapabilityData.Data)

	return tpm20Info{
		vendor:       strings.Trim(vendorInfo, "\x00"),
		manufacturer: vendor,
		fwMajor:      int((fw & 0xffff0000) >> 16),
		fwMinor:      int(fw & 0x0000ffff),
	}, nil
}

// Flushes a handle from TPM memory
func (tpm *TPM2) Flush(handle tpm2.TPMHandle) {
	tpm.logger.Debugf("tpm: flushing handle: 0x%x", handle)
	_, err := tpm2.FlushContext{FlushHandle: handle}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
	}
}

// Thanks, Google: https://github.com/google/go-attestation/blob/master/attest/tpm.go#L263
func intelEKURL(ekPub *rsa.PublicKey) string {
	pubHash := sha256.New()
	pubHash.Write(ekPub.N.Bytes())
	pubHash.Write([]byte{0x1, 0x00, 0x01})

	return intelEKCertServiceURL + url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))
}

// Downloads the EK certificate from the manufactuers EK cert service
func (tpm *TPM2) downloadEKCertFromManufacturer() ([]byte, error) {

	url := intelEKURL(tpm.ekRSAPubKey)
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
		tpm.logger.Error(err)
		return nil, err
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, resp.Body); err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	return buf.Bytes(), nil
}

// Creates a new signed blob storage key for the local TPM
// func (tpm *TPM2) ekCertBlobKey() string {
// 	return fmt.Sprintf("%s/%s", blobStorePrefix, tpm.ekBlobKey)
// }

// Creates a new signed blob storage key for an attestor TPM
func (tpm *TPM2) createEKCertBlobKey(domain, cn string) string {
	return fmt.Sprintf("%s/%s/%s", blobStorePrefix, domain, cn)
}

// Extracts a RSA Public Key from a TPM CreatePrimary response
func (tpm *TPM2) parsePrimaryRSA(
	response *tpm2.CreatePrimaryResponse) (Key, error) {

	ekPub, err := response.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	key, err := tpm.parseRSA(ekPub, nil)
	if err != nil {
		return key, err
	}
	key.Handle = response.ObjectHandle
	key.Name = response.Name
	key.BPublicBytes = response.OutPublic.Bytes()
	return key, nil
}

// Extracts an ECC Public Key from a TPM CreatePrimary response
func (tpm *TPM2) parsePrimaryECC(
	response *tpm2.CreatePrimaryResponse) (Key, error) {

	ekPub, err := response.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	key, err := tpm.parseECC(ekPub, nil)
	if err != nil {
		return key, err
	}
	key.Handle = response.ObjectHandle
	key.Name = response.Name
	key.BPublicBytes = response.OutPublic.Bytes()
	return key, nil
}

// Extracts the ECC public key from the public area of a TPM response
func (tpm *TPM2) parseECC(pub *tpm2.TPMTPublic, rsaPrivBlob []byte) (Key, error) {
	eccUnique, err := pub.Unique.ECC()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	eccPub, err := tpm2.ECDHPubKey(ecdh.P256(), &tpm2.TPMSECCPoint{
		X: eccUnique.X,
		Y: eccUnique.Y,
	})
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	eccPEM, err := tpm.ca.EncodePubKey(eccPub)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	return Key{
		Public:       *pub,
		ECCPubKey:    eccPub,
		PublicKeyPEM: eccPEM,
	}, nil
}

// Extracts the RSA public key from the public area of a TPM response
func (tpm *TPM2) parseRSA(pub *tpm2.TPMTPublic, rsaPrivBlob []byte) (Key, error) {
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	rsaDER, err := tpm.ca.EncodePubKey(rsaPub)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	rsaPEM, err := tpm.ca.EncodePEM(rsaDER)
	if err != nil {
		tpm.logger.Error(err)
		return Key{}, err
	}
	key := Key{
		Public:         *pub,
		RSAPubKey:      rsaPub,
		PublicKeyBytes: rsaDER,
		PublicKeyPEM:   rsaPEM,
	}
	if rsaPrivBlob != nil {
		// Private key is encrypted: TCG Part 3 (12.1.1)
		// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
		//
		// rsaPriv, err := tpm.ca.ParsePrivateKey(rsaPrivBlob)
		// if err != nil {
		// 	tpm.logger.Error(err)
		// 	return Key{}, err
		// }
		// rsaPrivPEM, err := tpm.ca.EncodePrivKeyPEM(rsaPrivBlob)
		// if err != nil {
		// 	tpm.logger.Error(err)
		// 	return Key{}, err
		// }
		//key.RSAPrivKey = rsaPriv
		//key.PrivateKeyPEM = rsaPrivPEM
		key.PrivateKeyBytes = rsaPrivBlob
	}
	return key, nil
}

// Returns the Endorsement Key (EK) policy secret
func (tpm *TPM2) ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}
	return err
}

// Encodes bytes to hexidecimal form
func (tpm *TPM2) Encode(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// Decodes hexidecimal form to byte array
func (tpm *TPM2) Decode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func (tpm *TPM2) DebugPrimaryKey(key Key) {
	tpm.logger.Debugf("--- Primary / Hierarchy Key ---")
	tpm.logger.Debugf("Handle: 0x%x", key.Handle)
	tpm.logger.Debugf("Name: 0x%x", key.Name.Buffer)
	tpm.logger.Debugf("Public: %+v", key.Public)
	tpm.logger.Debugf("Auth: %s", key.Auth)

	tpm.logger.Debug("RSA Public Key:")
	tpm.logger.Debugf("  Modulus: %d", key.RSAPubKey.N)
	tpm.logger.Debugf("  Exponent: %d", key.RSAPubKey.E)
}

func (tpm *TPM2) DebugAttestationKey(ak DerivedKey) {
	tpm.DebugPrimaryKey(ak.Key)
	tpm.logger.Debugf("\t--- Attestation Key (AK) ---")
	tpm.logger.Debugf("\tCreationHash: 0x%x", tpm.Encode(ak.CreationHash))
	tpm.logger.Debugf("\tCreationData: 0x%x", tpm.Encode(ak.CreationData))
	tpm.logger.Debugf("\tCreationTicket: 0x%x", tpm.Encode(ak.CreationTicket))
	tpm.logger.Debugf("\tPrivateKeyPEM: %s", ak.PrivateKeyPEM)
	tpm.logger.Debugf("\tPublicKeyPEM: %x", ak.PublicKeyPEM)
}
