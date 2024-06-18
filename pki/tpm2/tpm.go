package tpm2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/op/go-logging"
)

const (
	manufacturerIntel     = "Intel"
	intelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
)

var (
	EKCertIndex = tpm2.TPMHandle(0x01C00002) //  TCG specified location for RSA-EK-certificate.

	ErrEndorsementCertNotFound = errors.New("tpm: endorsement key certificate not found")
	ErrEndorsementKeyNotFound  = errors.New("tpm: endorsement key not found")
	ErrEKCertNotFound          = errors.New("tpm: endorsement key certificate not found")
	ErrInvalidEKCertFormat     = errors.New("tpm: invalid endorsement certificate format")
	ErrInvalidEKCert           = errors.New("tpm: failed to verify endorsement key certificate")
	ErrDeviceAlreadyOpen       = errors.New("tpm: device already open")
	ErrOpeningDevice           = errors.New("tpm: error opening device")
	ErrInvalidSessionType      = errors.New("tpm: invalid session type")

	ErrHashAlgorithmNotSupported = errors.New("TPM_RC_HASH (parameter 1): hash algorithm not supported or not appropriate")

	// The EK certificate may not exist on the TPM
	// and the manufactuter website may not be available
	// so try to load the cert from the local file system
	// as a last resort.
	EK_CERT_CN = "tpm-ek"
	EK_FILE    = "tpm-ek.bin"
)

type TrustedPlatformModule2 interface {
	RandomReader() (io.Reader, error)
	Random() ([]byte, error)
	ImportTSSFile(
		ekCertPath string,
		verify bool) (*x509.Certificate, error)
	ImportTSS(
		ekCertBytes []byte,
		verify bool) (*x509.Certificate, error)
	HMACAuthSessionWithKey(
		srkHandle tpm2.TPMHandle,
		srkPub tpm2.TPMTPublic,
		srkAuth []byte) (s tpm2.Session, close func() error, err error)
	HMACAuthSession(srkAuth []byte) (s tpm2.Session, close func() error, err error)
	SaltedHMACSession(handle tpm2.TPMIDHObject, pub tpm2.TPMTPublic) tpm2.Session
	HMACSession() tpm2.Session
	Unseal(
		srkHandle tpm2.TPMHandle,
		srkName tpm2.TPM2BName,
		srkPub tpm2.TPMTPublic,
		srkAuth []byte,
		createResponse *tpm2.CreateResponse,
		sealName, sealAuth []byte) ([]byte, error)
	Seal(
		srkHandle tpm2.TPMHandle,
		srkName tpm2.TPM2BName,
		srkPub tpm2.TPMTPublic,
		srkAuth, sealAuth, sealName, sealData []byte) (*tpm2.CreateResponse, error)
	CreateSRK(
		ekPub tpm2.TPMTPublic,
		password []byte) (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error)
	ECCSRK(
		ekHandle tpm2.TPMHandle,
		ekPub tpm2.TPMTPublic,
		password []byte) (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error)
	CreateAK(
		srkHandle tpm2.TPMHandle,
		srkName tpm2.TPM2BName,
		srkPub tpm2.TPMTPublic,
		srkAuth []byte) (*tpm2.CreateResponse, error)
	RSAEK() (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error)
	ECCEK() (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error)
	EKCert(srkAuth []byte) (*x509.Certificate, error)
	Capabilities() (tpm20Info, error)
	Init() error
	EKRSAPubKey() *rsa.PublicKey
	SetCertificateAuthority(ca ca.CertificateAuthority)
	Close() error
	Flush(handle tpm2.TPMHandle)
	ReadPCRs() (map[string][][]byte, error)
	ActivateCredential(
		ekHandle tpm2.TPMHandle,
		ekName tpm2.TPM2BName,
		srkHandle tpm2.TPMHandle,
		srkName tpm2.TPM2BName,
		srkPub tpm2.TPMTPublic,
		srkAuth []byte,
		credentialBlob tpm2.TPM2BIDObject,
		encryptedSecret tpm2.TPM2BEncryptedSecret) (*tpm2.ActivateCredentialResponse, error)
	// MakeCredential(
	// 	akHandle tpm2.TPMHandle,
	// 	akName tpm2.TPM2BName,
	// 	secret []byte) (tpm2.TPMHandle, tpm2.TPMTPublic, tpm2.TPMHandle, tpm2.TPM2BName, *tpm2.MakeCredentialResponse, error)
	MakeCredential(srkAuth, secret []byte) (
		tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, *tpm2.MakeCredentialResponse, error)
	Encode(bytes []byte) string
	Decode(s string) ([]byte, error)
	// MeasurementLog() (*EventLog, error)
	Measurements(logpath []byte) (*EventLog, error)
	ParseEKCertificate(ekCert []byte) (*x509.Certificate, error)
}

type TPM2 struct {
	logger      *logging.Logger
	config      *Config
	device      *os.File
	ca          ca.CertificateAuthority
	ekRSAPubKey *rsa.PublicKey
	ekECCPubKey *ecdh.PublicKey
	// ekECCPubKey *ecdsa.PublicKey
	transport transport.TPM

	TrustedPlatformModule2
}

// Opens a new socket to a Trusted Platform Module (TPM)
func New(logger *logging.Logger, config *Config) (TrustedPlatformModule2, error) {

	if config == nil || config.Device == "" {
		config.Device = "/dev/tpmrm0"
	}

	f, err := os.OpenFile(config.Device, os.O_RDWR, 0)
	if err != nil {
		logger.Error(err)
		return nil, ErrOpeningDevice
	}

	return &TPM2{
		logger:    logger,
		config:    config,
		device:    f,
		transport: transport.FromReadWriter(f)}, nil
}

func NewSimulation(logger *logging.Logger, config *Config) (TrustedPlatformModule2, error) {
	sim, err := simulator.Get()
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	return &TPM2{
		logger:    logger,
		config:    config,
		device:    nil,
		transport: transport.FromReadWriter(sim)}, nil
}

// Opens a new socket to a Trusted Platform Module (TPM) and uses the passed
// Privacy-CA to bootstrap the inital Root of Trust by verifying the Endorsement
// Certificate and ensuring the EK public key matches the public key in the certificate.
func NewTP(
	logger *logging.Logger,
	config *Config,
	CA ca.CertificateAuthority) (TrustedPlatformModule2, error) {

	if config == nil || config.Device == "" {
		config.Device = "/dev/tpmrm0"
	}

	f, err := os.OpenFile(config.Device, os.O_RDWR, 0)
	if err != nil {
		logger.Error(err)
		return nil, ErrOpeningDevice
	}

	return &TPM2{
		logger:    logger,
		config:    config,
		device:    f,
		transport: transport.FromReadWriter(f)}, nil
}

// Open a connection to the TPM and load the Endorsement Key (EK), EK RSA public key,
// and TPM manufacturer's x509 certificate that proves the EK originated from the TPM
// manufacturer.
//
// If the EK public key is not found in the Certificate Authority, it's loaded from
// TPM NVRAM and imported into the Cerficiate Authority.
//
// If the EK certificate is not found in the Certificate Authority, a 1st attempt loads
// it from TPM NVRAM, with a 2nd attempt to downloading it from the TPM manufacturer's
// website if it's not found in the TPM.
//
// The connection must be closed after the platform has been initialized to free
// the resources and allow other goroutines and / or processes to access the TPM.
//
// Manufacturer EK Certificate Services:
// Intel:    https://ekop.intel.com/ekcertservice
// AMD:      https://ftpm.amd.com/pki/aia
// // Qualcomm: https://ekcert.spserv.microsoft.com/EKCertificate/GetEKCertificate/v1
func NewTrustedPlatform(
	logger *logging.Logger,
	config *Config,
	CA ca.CertificateAuthority) (TrustedPlatformModule2, error) {

	if config == nil || config.Device == "" {
		config.Device = "/dev/tpmrm0"
	}

	f, err := os.OpenFile(config.Device, os.O_RDWR, 0)
	if err != nil {
		logger.Error(err)
		return nil, ErrOpeningDevice
	}

	return &TPM2{
		logger:    logger,
		config:    config,
		device:    f,
		transport: transport.FromReadWriter(f)}, nil
}

// Injects the Certificate Authority after instantiation
func (tpm *TPM2) SetCertificateAuthority(ca ca.CertificateAuthority) {
	tpm.ca = ca
}

// Returns the TPM Endorsement Key (EK) Public (Key
func (tp *TPM2) EKRSAPubKey() *rsa.PublicKey {
	return tp.ekRSAPubKey
}

// Initializes the TPM device by either loading an existing Endorsement Key
// and Attestation profile or creating a new EK and performing a new initialization.
//
// During initialization, the EK Issuer certificates are downloaded and imported into
// the Intermeidate Certificate Authority. The EK is verified to ensure it's issued
// by the TPM manufacturter. If valid, the EK is signed and stored in the CA signed
// artifacts store, initial platform measurements are taken and sealed to TPM PCRs.
func (tpm *TPM2) Init() error {

	tpm.logger.Info("tpm: retrieving endorsement key and certificate from certificate authority")

	// Check the CA for a signed EK cert
	certBytes, err := tpm.ca.SignedData(EK_CERT_CN)
	if err == ca.ErrCertNotFound {
		// Perform integrity check on the cert
		if err := tpm.ca.PersistentVerifySignature(EK_CERT_CN, certBytes); err != nil {
			return err
		}
		// // Return the signed EK cert from the CA
		// _, err := x509.ParseCertificate(certBytes)
		// return err
		return nil
	}
	if err != ca.ErrCertNotFound {
		return err
	}

	// No signed certificate in the CA, initialize and perform local attestation.
	if err != nil {
		if err == ca.ErrCertNotFound {
			if _, err := tpm.EKCert(nil); err != nil {
				return err
			}
			// if err := tpm.loadEKCert(); err != nil {
			// 	return err
			// }
			return nil
		}
		return err
	}

	// TPM and Certificate Authority already initalized
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

// Retrieve the Endorsement Key Certificate from the Certificate Authority.
// If the certificate can not be found, treat this as a first-start and
// try to load the cert from TPM NVRAM. If that fails, try to download the
// certificate from the Manufacturer's EK cert service. If that fails, try
// to load the certificate from the current working directory as a last resort.
func (tpm *TPM2) EKCert(srkAuth []byte) (*x509.Certificate, error) {

	tpm.logger.Debug("tpm: checking Certificate Authority for signed EK certificate")

	// Check the CA for a signed EK cert
	certBytes, err := tpm.ca.SignedData(EK_CERT_CN)
	if err == nil {
		// Perform integrity check on the cert
		if err := tpm.ca.PersistentVerifySignature(EK_CERT_CN, certBytes); err != nil {
			return nil, err
		}
		tpm.logger.Info("tpm: loading EK certificate from Certificate Authority")
		// Return the signed EK cert from the CA
		return x509.ParseCertificate(certBytes)
	}
	if err != ca.ErrCertNotFound {
		return nil, err
	}

	// No EK found in the CA. Treat this as an initial platform setup...

	// No certificate found in the CA, check TPM NVRAM
	var srkHandle tpm2.TPMHandle
	var srkPub tpm2.TPMTPublic
	if srkAuth == nil {
		_, _, ekPub, err := tpm.RSAEK()
		if err != nil {
			return nil, err
		}
		srkHandle, _, srkPub, err = tpm.CreateSRK(ekPub, srkAuth)
		if err != nil {
			return nil, err
		}
	}

	// Start session using SRK
	session, closer, err := tpm.HMACAuthSessionWithKey(srkHandle, srkPub, srkAuth)
	if err != nil {
		return nil, err
	}

	defer closer()

	// Attempt to read the cert from NVRAM
	response, err := tpm2.NVReadPublic{
		NVIndex: EKCertIndex,
	}.Execute(tpm.transport, session)
	if err != nil {
		tpm.logger.Error(err)

		// No EK cert found in NVRAM. Try downloading from the manufacturer EK certificate service
		manufacuterCert, err := tpm.downloadEKCertFromManufacturer()
		if err == nil {
			return x509.ParseCertificate(manufacuterCert)
		}

		// Final attempt: look for a raw TSS formatted certificate in the current working directory
		if _, err := os.Stat(EK_FILE); errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return tpm.ImportTSSFile(EK_FILE, true)

	} else {
		certBytes = response.NVPublic.Bytes()
	}

	// Make sure the certificate is a valid x509 cert
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	// Import the EK public key to the CA
	tpm.logger.Infof("tpm: importing EK Public Key to Certificate Authority")
	if err := tpm.ca.ImportPubKey(EK_CERT_CN, cert.PublicKey); err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Sign and save the EK certificate to the CA
	tpm.logger.Infof("tpm: signing EK certificate and importing to Certificate Authority")
	if _, err := tpm.ca.PersistentSign(EK_CERT_CN, certBytes, true); err != nil {
		return nil, err
	}

	return cert, nil
}

// Returns an Elliptical Curve Cryptography (ECC) Endorsement Key (EK) in alignment
// with the TCG reference ECC-P256 EK template.
func (tpm *TPM2) ECCEK() (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error) {

	tpm.logger.Debug("tpm: creating ECC Endorsement Key (EK)")

	var handle tpm2.TPMHandle
	var name tpm2.TPM2BName
	var public tpm2.TPMTPublic

	ekCreate := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}
	response, err := ekCreate.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}
	//defer tpm.Flush(response.ObjectHandle)

	ekPub, err := response.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}

	eccUnique, err := ekPub.Unique.ECC()
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}

	eccPub, err := tpm2.ECDHPubKey(ecdh.P256(), &tpm2.TPMSECCPoint{
		X: eccUnique.X,
		Y: eccUnique.Y,
	})
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}

	tpm.ekECCPubKey = eccPub

	tpm.logger.Infof("EK handle: 0x%x", response.ObjectHandle)
	tpm.logger.Infof("EK ECC public key:\nX: %x\nY: %x\n", eccUnique.X.Buffer, eccUnique.Y.Buffer)

	return response.ObjectHandle, response.Name, *ekPub, nil
}

// Creates an Rivest Shamir Adleman (RSA) Endorsement Key (EK) in alignment with
// the TCG reference RSA-2048 EK template.
func (tpm *TPM2) RSAEK() (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error) {

	tpm.logger.Debug("tpm: creating RSA Endorsement Key (EK)")

	var handle tpm2.TPMHandle
	var name tpm2.TPM2BName
	var public tpm2.TPMTPublic

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}

	response, err := createPrimary.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}
	defer tpm.Flush(response.ObjectHandle)

	ekPub, err := response.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}

	rsaDetail, err := ekPub.Parameters.RSADetail()
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}
	rsaUnique, err := ekPub.Unique.RSA()
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, public, err
	}
	tpm.ekRSAPubKey = rsaPub

	tpm.logger.Infof("EK handle: 0x%x", response.ObjectHandle)
	tpm.logger.Infof("EK RSA public key:\n%x\n", rsaPub)

	// switch ekPub.Type {
	// case tpm2.TPMAlgRSA:
	// 	rsaDetail, err := ekPub.Parameters.RSADetail()
	// 	if err != nil {
	// 		tpm.logger.Error(err)
	// 		return handle, name, public, err
	// 	}
	// 	rsaUnique, err := ekPub.Unique.RSA()
	// 	if err != nil {
	// 		tpm.logger.Error(err)
	// 		return handle, name, public, err
	// 	}
	// 	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	// 	if err != nil {
	// 		tpm.logger.Error(err)
	// 		return handle, name, public, err
	// 	}
	// 	tpm.ekRSAPubKey = rsaPub
	// 	tpm.logger.Infof("EK RSA public key:\n%x\n", rsaPub)

	// case tpm2.TPMAlgECC:
	// 	// eccDetail, err := ekPub.Parameters.ECCDetail()
	// 	// if err != nil {
	// 	// 	tpm.logger.Error(err)
	// 	// 	return handle, name, public, err
	// 	// }
	// 	// eccUnique, err := ekPub.Unique.ECC()
	// 	// if err != nil {
	// 	// 	tpm.logger.Error(err)
	// 	// 	return handle, name, public, err
	// 	// }
	// 	// eccPub, err := tpm2.ECCPub(eccDetail, eccUnique)
	// 	// if err != nil {
	// 	// 	tpm.logger.Error(err)
	// 	// 	return handle, name, public, err
	// 	// }
	// 	// tpm.ekECCPubKey = eccPub
	// 	// tpm.logger.Infof("EK ECC public key:\n%x\n%x\n", eccPub.X, eccPub.Y)
	// }

	// if err := os.WriteFile("ek.ctx", pekPub, 0644); err != nil {
	// 	tpm.logger.Fatalf("writing context: %v", err)
	// }

	// pubDER, err := x509.MarshalPKIXPublicKey(ekPub)
	// if err != nil {
	// 	tpm.logger.Fatalf("encoding public key: %v", err)
	// }

	// b := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	// pem.Encode(os.Stdout, b)

	// cert, err := x509.ParseCertificate(ekoutPub)

	return response.ObjectHandle, response.Name, *ekPub, nil
}

// Create new ECC Storage Root Key (SRK). Returns the SRK handle to be used
// in subsequent calls / operations and requires a call to Flush when done.
// NOTE: TCG spec disallows sealing to endorsement keys
func (tpm *TPM2) ECCSRK(
	ekHandle tpm2.TPMHandle,
	ekPub tpm2.TPMTPublic,
	password []byte) (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error) {

	var name tpm2.TPM2BName
	var public tpm2.TPMTPublic

	tpm.logger.Debug("tpm: creating new Storage Root Key (SRK)")

	// New password protected SRK template
	createPrimaryCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		// InSensitive: tpm2.TPM2BSensitiveCreate{
		// 	Sensitive: &tpm2.TPMSSensitiveCreate{
		// 		UserAuth: tpm2.TPM2BAuth{
		// 			Buffer: password,
		// 		},
		// 	},
		// },
	}

	// Execute the create SRK command
	var srk *tpm2.CreatePrimaryResponse
	var err error
	if tpm.config.EncryptSession {
		srk, err = createPrimaryCMD.Execute(
			tpm.transport,
			tpm.SaltedHMACSession(ekHandle, ekPub))
	} else {
		srk, err = createPrimaryCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return srk.ObjectHandle, name, public, err
	}
	//defer tpm.Flush(srk.ObjectHandle)

	// Retrieve the response
	srkPub, err := srk.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return srk.ObjectHandle, name, public, err
	}

	// tpm2.TPMHandle, tpm2.TPMTPublic, tpm2.TPMHandle, tpm2.TPM2BName, *tpm2.MakeCredentialResponse, error

	// saveContextCMD := tpm2.ContextSave{
	// 	SaveHandle: srk.ObjectHandle,
	// }
	// saveContextResponse, err := saveContextCMD.Execute(tpm.transport)
	// if err != nil {
	// 	return srk.ObjectHandle, name, public, err
	// }
	// saveContextResponse.Context

	tpm.logger.Debugf("tpm: created ECC Storage Root Key (SRK) with handle: 0x%x", srk.ObjectHandle)

	return srk.ObjectHandle, srk.Name, *srkPub, nil
}

// Create new Storage Root Key (SRK). Returns the SRK handle to be used
// in subsequent calls / operations and requires a call to Flush
// when done.
// NOTE: TCG spec disallows sealing to endorsement keys
func (tpm *TPM2) CreateSRK(
	ekPub tpm2.TPMTPublic,
	password []byte) (tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, error) {

	tpm.logger.Debug("tpm: creating new RSA Storage Root Key (SRK)")

	// New password protected SRK template
	createPrimaryCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		// CreationPCR: tpm2.TPMLPCRSelection{
		// 	PCRSelections: []tpm2.TPMSPCRSelection{
		// 		{
		// 			Hash:      tpm2.TPMAlgSHA256,
		// 			PCRSelect: tpm2.PCClientCompatible.PCRs(debugPCR),
		// 		},
		// 	},
		// },
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: password,
				},
			},
		},
	}

	// Execute the create SRK command
	var srk *tpm2.CreatePrimaryResponse
	var err error
	if tpm.config.EncryptSession {
		srk, err = createPrimaryCMD.Execute(
			tpm.transport,
			tpm.SaltedHMACSession(srk.ObjectHandle, ekPub))
	} else {
		srk, err = createPrimaryCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return srk.ObjectHandle, tpm2.TPM2BName{}, tpm2.TPMTPublic{}, err
	}
	// defer tpm.Flush(srk.ObjectHandle)

	// Retrieve the response
	srkPub, err := srk.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return srk.ObjectHandle, tpm2.TPM2BName{}, tpm2.TPMTPublic{}, err
	}

	tpm.logger.Debugf("tpm: created SRK with handle 0x%x", srk.ObjectHandle)

	return srk.ObjectHandle, srk.Name, *srkPub, nil
}

// Creates a new Attestation Key (AK)
func (tpm *TPM2) CreateAK(
	srkHandle tpm2.TPMHandle,
	srkName tpm2.TPM2BName,
	srkPub tpm2.TPMTPublic,
	srkAuth []byte) (*tpm2.CreateResponse, error) {

	tpm.logger.Debug("tpm: creating new Attestation Key (AK)")

	var err error
	session, closer, err := tpm.HMACAuthSessionWithKey(srkHandle, srkPub, srkAuth)
	defer closer()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	createKeyCMD := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(rsaTemplate),
		//
		// Works, but not sure about using PCR yet
		//
		// CreationPCR: tpm2.TPMLPCRSelection{
		// 	PCRSelections: []tpm2.TPMSPCRSelection{
		// 		{
		// 			Hash:      tpm2.TPMAlgSHA256,
		// 			PCRSelect: tpm2.PCClientCompatible.PCRs(debugPCR),
		// 		},
		// 	},
		// },
		//
		// Invalid config
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
			tpm.SaltedHMACSession(srkHandle, srkPub))
	} else {
		createKeyResponse, err = createKeyCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	akPub, err := createKeyResponse.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	var akRSAPubKey *rsa.PublicKey
	var akECCPubKey *ecdsa.PublicKey

	switch akPub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := akPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		rsaUnique, err := akPub.Unique.RSA()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		akRSAPubKey = rsaPub
		tpm.logger.Infof("EK RSA public key:\n%x\n", rsaPub)

	case tpm2.TPMAlgECC:
		// eccDetail, err := akPub.Parameters.ECCDetail()
		// if err != nil {
		// 	tpm.logger.Error(err)
		// 	return nil, err
		// }
		// eccUnique, err := akPub.Unique.ECC()
		// if err != nil {
		// 	tpm.logger.Error(err)
		// 	return nil, err
		// }
		// eccPub, err := tpm2.ECCPub(eccDetail, eccUnique)
		// if err != nil {
		// 	tpm.logger.Error(err)
		// 	return nil, err
		// }
		// akECCPubKey = eccPub
		tpm.logger.Infof("EK ECC public key:\n%x\n%x\n", akECCPubKey.X, akECCPubKey.Y)
	}

	b, err := x509.MarshalPKIXPublicKey(akRSAPubKey)
	if err != nil {
		log.Fatalf("Unable to convert akpub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	log.Printf("akPub RSA: \n%v", string(akPubPEM))

	return createKeyResponse, nil
}

// Encodes bytes to hexidecimal form
func (tpm *TPM2) Encode(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// Decodes hexidecimal form to byte array
func (tpm *TPM2) Decode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	if err != nil {
		log.Printf("ekPolicy error: %s", err)
	}
	return err
}

// Verifies a secret that was generated by an Attestation Key (AK) for the purposes
// of remote attestation:
// https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html
func (tpm *TPM2) ActivateCredential(
	ekHandle tpm2.TPMHandle,
	ekName tpm2.TPM2BName,
	srkHandle tpm2.TPMHandle,
	srkName tpm2.TPM2BName,
	srkPub tpm2.TPMTPublic,
	srkAuth []byte,
	credentialBlob tpm2.TPM2BIDObject,
	encryptedSecret tpm2.TPM2BEncryptedSecret) (*tpm2.ActivateCredentialResponse, error) {

	tpm.logger.Debugf("tpm: activating credential: %x", tpm.Encode(encryptedSecret.Buffer))

	// loadBlobCmd := tpm2.Load{
	// 	ParentHandle: tpm2.AuthHandle{
	// 		Handle: srkHandle,
	// 		Name:   srkName,
	// 		Auth:   session,
	// 	},
	// 	InPrivate: createResponse.OutPrivate,
	// 	InPublic:  createResponse.OutPublic,
	// }
	// loadResponse, err := loadBlobCmd.Execute(tpm.transport)
	// if err != nil {
	// 	tpm.logger.Error(err)
	// 	return nil, err
	// }
	// defer tpm.Flush(loadResponse.ObjectHandle)

	// var err error
	// session, closer, err := tpm.HMACAuthSessionWithKey(srkHandle, srkPub, srkAuth)
	// defer closer()
	// if err != nil {
	// 	tpm.logger.Error(err)
	// 	return nil, err
	// }

	// tpm.logger.Debugf("tpm: ECC Endorsement Key (EK) handle: 0x%x", ekHandle)
	// tpm.logger.Debugf("tpm: ECC Endorsement Key (EK) name: 0x%x", ekName)
	// tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) handle: 0x%x", srkHandle)
	// tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) name: 0x%x", srkName)
	// tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) public: 0x%x", srkPub)
	// tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) auth: %s", srkAuth)

	activateCredentialCMD := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: srkHandle,
			Name:   srkName,
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: ekHandle,
			Name:   ekName,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		CredentialBlob: credentialBlob,
		Secret:         encryptedSecret,
	}

	response, err := activateCredentialCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	return response, nil
}

// Generates a new credential challenge
func (tpm *TPM2) MakeCredential(srkAuth, secret []byte) (
	tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMHandle, tpm2.TPM2BName, tpm2.TPMTPublic, *tpm2.MakeCredentialResponse, error) {

	var handle tpm2.TPMHandle
	var name tpm2.TPM2BName
	var public tpm2.TPMTPublic

	tpm.logger.Debug("tpm: making credential challenge: *************")

	tpm.logger.Debug("tpm: creating Elliptical Curve Cryptography (ECC) Endorsement Key (EK)")

	ekHandle, ekName, ekPub, err := tpm.ECCEK()
	if err != nil {
		return handle, name, handle, name, public, nil, err
	}
	// defer tpm.Flush(ekHandle)

	tpm.logger.Debug("tpm: creating Storage Root Key (SRK) under ECC Endorsement Key (EK)")

	srkHandle, srkName, srkPub, err := tpm.ECCSRK(ekHandle, ekPub, srkAuth)
	// defer tpm.Flush(srkHandle)

	makeCredentialCMD := tpm2.MakeCredential{
		Handle:      ekHandle,
		ObjectNamae: srkName,
		Credential:  tpm2.TPM2BDigest{Buffer: secret},
	}
	response, err := makeCredentialCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return handle, name, handle, name, public, nil, err
	}

	tpm.logger.Debugf("tpm: ECC Endorsement Key (EK) handle: 0x%x", ekHandle)
	tpm.logger.Debugf("tpm: ECC Endorsement Key (EK) name: 0x%x", ekName)
	tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) handle: 0x%x", srkHandle)
	tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) name: 0x%x", srkName)
	tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) public: 0x%x", srkPub)
	tpm.logger.Debugf("tpm: ECC Storage Root Key (SRK) auth: %s", srkAuth)

	return ekHandle, ekName, srkHandle, srkName, srkPub, response, nil
}

// Decrypts an encrypted blob using the requested Attestation Key (AK)
// pointed to by akHandle.
func (tpm *TPM2) RSADecrypt(
	akHandle tpm2.TPMHandle,
	blob []byte) ([]byte, error) {

	decryptCmd := tpm2.RSADecrypt{
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
	}
	response, err := decryptCmd.Execute(tpm.transport)
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

	encryptCmd := tpm2.RSAEncrypt{
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
	}
	encryptRsp, err := encryptCmd.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return encryptRsp.OutData.Buffer, nil
}

// Creates a new Attestment Key
func (tpm *TPM2) Seal(
	srkHandle tpm2.TPMHandle,
	srkName tpm2.TPM2BName,
	srkPub tpm2.TPMTPublic,
	srkAuth, sealAuth, sealName, sealData []byte) (*tpm2.CreateResponse, error) {

	tpm.logger.Debugf("tpm: sealing %s with SRK handle 0x%x",
		sealName, srkHandle)

	session, closer, err := tpm.HMACAuthSessionWithKey(srkHandle, srkPub, srkAuth)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer()

	createBlobCMD := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
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
	srkHandle tpm2.TPMHandle,
	srkName tpm2.TPM2BName,
	srkPub tpm2.TPMTPublic,
	srkAuth []byte,
	createResponse *tpm2.CreateResponse,
	sealName, sealAuth []byte) ([]byte, error) {

	tpm.logger.Debugf("tpm: unsealing %s", string(sealName))

	// Create authenticated session using SRK
	var session tpm2.Session
	var closer func() error
	session, closer, err := tpm.HMACAuthSessionWithKey(srkHandle, srkPub, srkAuth)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer()

	// Load the sealed blob
	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
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
		session, closer, err = tpm.HMACAuthSessionWithKey(srkHandle, srkPub, sealAuth)
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

	return unsealResponse.OutData.Buffer, nil
}

// Creates a "one-time", unauthenticated, NON-encrypted HMAC session to the TPM
func (tpm *TPM2) HMACSession() tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16,
		tpm2.AESEncryption(128, tpm2.EncryptInOut))
}

// Creates a "one-time", unauthenticated, NON-encrypted HMAC session to the TPM for reading
func (tpm *TPM2) HMACSessionOut() tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16,
		tpm2.AESEncryption(128, tpm2.EncryptOut))
}

// Creates a "one-time", unauthenticated, NON-encrypted HMAC session to the TPM for reading
func (tpm *TPM2) HMACSessionIn() tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16,
		tpm2.AESEncryption(128, tpm2.EncryptIn))
}

// Creates a "one-time", unauthenticated, encrypted HMAC session to the TPM. Bus communication
// between the CPU <-> TPM uses encrypted HMAC session seed.
func (tpm *TPM2) SaltedHMACSession(handle tpm2.TPMIDHObject, pub tpm2.TPMTPublic) tpm2.Session {
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
		tpm2.Salted(handle, pub))
}

// Creates a re-usable, authenticated, NON-encrypted HMAC session to the TPM.
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

// Creates a new "one-time" encrypted, authenticated, salted HMAC session, using the SRK as the salt.
// The communication bus between the CPU <-> TPM is encrypted.
func (tpm *TPM2) HMACAuthSessionWithKey(
	srkHandle tpm2.TPMHandle,
	srkPub tpm2.TPMTPublic,
	srkAuth []byte) (s tpm2.Session, close func() error, err error) {

	if tpm.config.EncryptSession {
		return tpm2.HMACSession(
			tpm.transport,
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(srkAuth),
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut),
			tpm2.Salted(srkHandle, srkPub))
	}
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Auth(srkAuth),
		tpm2.AESEncryption(
			128,
			tpm2.EncryptInOut))
}

// Creates a new "one-time" encrypted, authenticated, "bound" HMAC session using a
// primary key (EK or SRK). The communication bus between the CPU <-> TPM is encrypted.
// Bound specifies that this session's session key should depend on the auth
// // value of the given object.
// func (tpm *TPM2) BoundAuthHMACSession(
// 	primaryKey *tpm2.CreatePrimaryResponse,
// 	srkAuth []byte) (s tpm2.Session, close func() error, err error) {

// 	return tpm2.HMACSession(
// 		tpm.transport,
// 		tpm2.TPMAlgSHA256,
// 		16,
// 		tpm2.Auth(srkAuth),
// 		tpm2.AESEncryption(
// 			128,
// 			tpm2.EncryptOut),
// 		tpm2.Bound(primaryKey.ObjectHandle, primaryKey.Name, srkAuth))
// }

func (tpm *TPM2) BoundHMACSession(
	handle tpm2.TPMHandle,
	name tpm2.TPM2BName,
	srkAuth []byte) (s tpm2.Session, close func() error, err error) {

	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.AESEncryption(
			128,
			tpm2.EncryptOut),
		tpm2.Bound(handle, name, srkAuth))
}

// Returns a reader capable of reading random bytes from the TPM. Enable
// the Encrypt configuration option to encrypt the communication bus between
// CPU <-> TPM.
func (tp *TPM2) RandomReader() (io.Reader, error) {

	// Use golang runtime random entropy if
	// TPM entropy isn't enabled
	if !tp.config.UseEntropy {
		return rand.Reader, nil
	}

	tp.logger.Info("tpm: random reader getting bytes from TPM")

	if tp.device != nil {
		tp.logger.Fatal(ErrDeviceAlreadyOpen)
	}

	// Create a new TPM transport and random reader
	// rwr := transport.FromReadWriter(tp.dev)
	reader := NewRandomReader(tp.transport)

	// Encrypt the sesion using the EK
	if tp.config.EncryptSession {

		tp.logger.Info("encrypting TPM <-> CPU session using endorsement key")

		createEKCmd := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createEKCmd.PrimaryHandle,
			}
			_, _ = flushContextCmd.Execute(tp.transport)
		}()

		createEKRsp, err := createEKCmd.Execute(tp.transport)
		if err != nil {
			fmt.Printf("can't acquire acquire ek %v", err)
			return nil, err
		}
		encryptionPub, err := createEKRsp.OutPublic.Contents()
		if err != nil {
			fmt.Printf("can't create ekpub blob %v", err)
			return nil, err
		}
		reader.EncryptionHandle = createEKRsp.ObjectHandle
		reader.EncryptionPub = encryptionPub
	}

	return reader, nil
}

// Generates a random string
func (tp *TPM2) Random() ([]byte, error) {

	randomBytes := make([]byte, 32)

	// Read random bytes from the TPM
	// reader, err := tp.RandomReader()
	// if err != nil {
	// 	return nil, err
	// }

	reader, err := tp.RandomReader()
	if err != nil {
		return nil, err
	}

	// Read in random bytes from the TPM
	n, err := reader.Read(randomBytes)
	if err != nil {
		fmt.Printf("%v\n", err)
		return nil, err
	}

	tp.logger.Debugf("read %d random chars", n)

	return randomBytes, nil

	// privkey, err := rsa.GenerateKey(r, 2048)
	// if err != nil {
	// 	fmt.Printf("%v\n", err)
	// 	return nil, err
	// }

	// keyPEM := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "RSA PRIVATE KEY",
	// 		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	// 	},
	// )
	// fmt.Printf("RSA Key: \n%s\n", keyPEM)

	// return keyPEM, nil
}

// Imports a raw TSS formatted EK certificate file into
// the Certificate Authority from disk.
func (tpm *TPM2) ImportTSSFile(
	ekCertPath string,
	verify bool) (*x509.Certificate, error) {

	tpm.logger.Info("Attemping to load Endorsement Key (EK) Certificate from local disk: %s", ekCertPath)
	bytes, err := os.ReadFile(ekCertPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrEKCertNotFound
		}
		return nil, err
	}
	return tpm.ImportTSS(bytes, verify)
}

// Imports a raw TSS formatted EK certificate file into
// the Certificate Authority using a parse byte array.
func (tpm *TPM2) ImportTSS(
	ekCertBytes []byte,
	verify bool) (*x509.Certificate, error) {

	tpm.logger.Info("tpm: decoding endorsement key")

	// Decode the EK
	decoded := make([]byte, len(ekCertBytes))
	n, err := base64.StdEncoding.Decode(decoded, ekCertBytes)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrInvalidEKCertFormat
	}

	tpm.logger.Info("tpm: parsing endorsement key")

	// Parse the x509 certificate from the decoded EK
	ekCert, err := tpm.ParseEKCertificate(decoded)
	if err != nil {
		return nil, err
	}

	// Unhandled critical extensions cause Verify to fail
	for _, uce := range ekCert.UnhandledCriticalExtensions {
		tpm.logger.Debugf("tpm: ek certificate contains unhandled critical extention: %s",
			uce.String())
	}
	ekCert.UnhandledCriticalExtensions = nil

	// Verify the endorsement key certificate
	if verify {
		valid, err := tpm.ca.Verify(ekCert, &EK_CERT_CN)
		if err != nil {
			if _, ok := err.(x509.UnknownAuthorityError); ok {

				tpm.logger.Info("tpm: importing Issuer CA certificates")

				if err := tpm.ca.ImportIssuingCAs(ekCert, &EK_CERT_CN, ekCert); err != nil {
					return nil, err
				}

				tpm.logger.Info("tpm: verifying endorsement key")

				valid, err := tpm.ca.Verify(ekCert, &EK_CERT_CN)
				if err != nil {
					return nil, err
				}
				if !valid {
					return nil, ErrInvalidEKCert
				}
			} else {
				return nil, err
			}
		}
		if !valid {
			return nil, ErrInvalidEKCert
		}
	}

	// Intel EK: This is failing with x509: unhandled critical extension...
	//
	// ImportCN calls ImportDER, which uses the ekCert.Raw DER
	// encoded bytes, which has ekCert.UnhandledCriticalExtensions.
	// Rather than hacking the CA code to allow unhandled critical
	// extensions, "manually" verify and import the EK PEM using
	// Verify, EncodePEM, and ImportPEM instead...
	//
	// if err := tp.ca.ImportCN(EK_CERT_CN, ekCert); err != nil {
	// 	return nil, err
	// }

	// All EK CA certs are imported into the Certificate
	// Authority trust store, now verify the EK certificate.
	valid, err := tpm.ca.Verify(ekCert, &EK_CERT_CN)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	if !valid {
		return nil, ca.ErrCertInvalid
	}
	tpm.logger.Infof("successfully verified endorsement key certificate: %s", EK_CERT_CN)

	// Encode the EK cert to PEM and import it into the CA
	pemBytes, err := tpm.ca.EncodePEM(ekCert.Raw)
	if err != nil {
		return nil, err
	}
	if err := tpm.ca.ImportPEM(EK_CERT_CN, pemBytes); err != nil {
		return nil, err
	}

	tpm.logger.Debug(pemBytes)

	tpm.logger.Info("tpm: endorsement key imported to certificate authority")

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
			encoded := hex.EncodeToString(buffer)

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
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: handle,
	}
	_, err := flushContextCmd.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
	}
}

// Closes the connection to the TPM
func (tp *TPM2) Close() error {
	tp.logger.Info("tpm: closing connection")
	if tp.device != nil {
		if err := tp.device.Close(); err != nil {
			tp.logger.Error(err)
		}
		tp.device = nil
	}
	return nil
}

// ParseEKCertificate parses a raw DER encoded EK certificate blob.
// Thanks, Google: https://github.com/google/go-attestation/blob/master/attest/tpm.go#L221
func (tpm *TPM2) ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	var wasWrapped bool

	// TCG PC Specific Implementation section 7.3.2 specifies
	// a prefix when storing a certificate in NVRAM. We look
	// for and unwrap the certificate if its present.
	if len(ekCert) > 5 && bytes.Equal(ekCert[:3], []byte{0x10, 0x01, 0x00}) {
		certLen := int(binary.BigEndian.Uint16(ekCert[3:5]))
		if len(ekCert) < certLen+5 {
			return nil, fmt.Errorf("tpm: parsing nvram header: ekCert size %d smaller than specified cert length %d", len(ekCert), certLen)
		}
		ekCert = ekCert[5 : 5+certLen]
		wasWrapped = true
	}

	// If the cert parses fine without any changes, we are G2G.
	if c, err := x509.ParseCertificate(ekCert); err == nil {
		return c, nil
	}
	// There might be trailing nonsense in the cert, which Go
	// does not parse correctly. As ASN1 data is TLV encoded, we should
	// be able to just get the certificate, and then send that to Go's
	// certificate parser.
	var cert struct {
		Raw asn1.RawContent
	}
	if _, err := asn1.UnmarshalWithParams(ekCert, &cert, "lax"); err != nil {
		return nil, fmt.Errorf("tpm: asn1.Unmarshal() failed: %v, wasWrapped=%v", err, wasWrapped)
	}

	c, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("tpm: x509.ParseCertificate() failed: %v", err)
	}
	return c, nil
}

// Thanks, Google: https://github.com/google/go-attestation/blob/master/attest/tpm.go#L263
func intelEKURL(ekPub *rsa.PublicKey) string {
	pubHash := sha256.New()
	pubHash.Write(ekPub.N.Bytes())
	pubHash.Write([]byte{0x1, 0x00, 0x01})

	return intelEKCertServiceURL + url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))
}

// Downloads the EK certificate from the manufactuers EK cert service
// TODO: Add support for other manufacturers
// Google :(
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
		tpm.logger.Error("tpm: error downloading EK certificate from manufacturer: http.StatusCode: %d, body: %s",
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
