package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	// TPM_RC_SIGNATURE (parameter 2): the signature is not valid
	ErrInvalidSignature = errors.New("tpm: invalid signature")
)

// Creates a TCG_CSR_IDEVID structure in alignment with the TCG
// TPM 2.0 Keys for Device Identity and Attestation - Section 13.1 -
// TCG-CSR-IDEVID.
func (tpm *TPM2) CreateTCG_CSR_IDEVID(
	ekCert *x509.Certificate,
	akAttrs *keystore.KeyAttributes,
	idevidAttrs *keystore.KeyAttributes) (TCG_CSR_IDEVID, error) {

	var signerAttrs *keystore.KeyAttributes

	enrollmentStrategy := ParseIdentityProvisioningStrategy(tpm.config.IdentityProvisioningStrategy)

	switch enrollmentStrategy {
	case EnrollmentStrategyIAK:
		signerAttrs = akAttrs
	case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
		signerAttrs = idevidAttrs
	default:
		return TCG_CSR_IDEVID{}, ErrInvalidEnrollmentStrategy
	}

	tcgContent := &TCG_IDEVID_CONTENT{}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	var padding []byte
	var padSz uint32
	var contents uint32
	if tpm.config.IDevID.Pad {
		// // Payload is followed by padSz bytes of random data here
		// to make the structure size a multiple of 16 bytes.
		numSizeFields := 10
		sz := content.ProdModelSz + content.ProdSerialSz +
			content.ProdCaDataSz + content.BootEvntLogSz +
			content.EkCertSZ + content.AttestPubSZ + content.AtCreateTktSZ +
			content.AtCertifyInfoSZ + content.AtCertifyInfoSignatureSZ +
			content.PadSz
		contents = sz + uint32(numSizeFields*4)
		padSz = uint32(contents % 16)
		padding = make([]byte, padSz)
		for i := uint32(0); i < padSz; i++ {
			padding[i] = '='
		}
	}

	binary.BigEndian.PutUint32(tcgContent.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(tcgContent.HashAlgoId[:], content.HashAlgoId)
	binary.BigEndian.PutUint32(tcgContent.HashSz[:], content.HashSz)

	// Hash of all that follows is placed here
	binary.BigEndian.PutUint32(tcgContent.ProdModelSz[:], content.ProdModelSz)
	binary.BigEndian.PutUint32(tcgContent.ProdSerialSz[:], content.ProdSerialSz)
	binary.BigEndian.PutUint32(tcgContent.ProdCaDataSz[:], content.ProdCaDataSz)
	binary.BigEndian.PutUint32(tcgContent.BootEvntLogSz[:], content.BootEvntLogSz)
	binary.BigEndian.PutUint32(tcgContent.EkCertSZ[:], content.EkCertSZ)
	binary.BigEndian.PutUint32(tcgContent.AttestPubSZ[:], content.AttestPubSZ)
	binary.BigEndian.PutUint32(tcgContent.AtCreateTktSZ[:], content.AtCreateTktSZ)
	binary.BigEndian.PutUint32(tcgContent.AtCertifyInfoSZ[:], content.AtCertifyInfoSZ)
	binary.BigEndian.PutUint32(tcgContent.AtCertifyInfoSignatureSZ[:], content.AtCertifyInfoSignatureSZ)
	binary.BigEndian.PutUint32(tcgContent.SigningPubSZ[:], content.SigningPubSZ)
	binary.BigEndian.PutUint32(tcgContent.SgnCertifyInfoSZ[:], content.SgnCertifyInfoSZ)
	binary.BigEndian.PutUint32(tcgContent.SgnCertifyInfoSignatureSZ[:], content.SgnCertifyInfoSignatureSZ)
	binary.BigEndian.PutUint32(tcgContent.PadSz[:], padSz)

	tcgContent.ProdModel = make([]byte, content.ProdModelSz)
	copy(tcgContent.ProdModel, content.ProdModel)

	tcgContent.ProdSerial = make([]byte, content.ProdSerialSz)
	copy(tcgContent.ProdSerial, content.ProdSerial)

	tcgContent.ProdCaData = make([]byte, content.ProdCaDataSz)
	copy(tcgContent.ProdCaData, content.ProdCaData)

	tcgContent.BootEvntLog = make([]byte, content.BootEvntLogSz)
	copy(tcgContent.BootEvntLog, content.BootEvntLog)

	tcgContent.EkCert = make([]byte, content.EkCertSZ)
	copy(tcgContent.EkCert, content.EkCert)

	tcgContent.AttestPub = make([]byte, content.AttestPubSZ)
	copy(tcgContent.AttestPub, content.AttestPub)

	tcgContent.AtCreateTkt = make([]byte, content.AtCreateTktSZ)
	copy(tcgContent.AtCreateTkt, content.AtCreateTkt)

	tcgContent.AtCertifyInfo = make([]byte, content.AtCertifyInfoSZ)
	copy(tcgContent.AtCertifyInfo, content.AtCertifyInfo)

	tcgContent.AtCertifyInfoSig = make([]byte, content.AtCertifyInfoSignatureSZ)
	copy(tcgContent.AtCertifyInfoSig, content.AtCertifyInfoSig)

	tcgContent.SigningPub = make([]byte, content.SigningPubSZ)
	copy(tcgContent.SigningPub, content.SigningPub)

	tcgContent.SgnCertifyInfo = make([]byte, content.SgnCertifyInfoSZ)
	copy(tcgContent.SgnCertifyInfo, content.SgnCertifyInfo)

	tcgContent.SgnCertifyInfoSig = make([]byte, content.SgnCertifyInfoSignatureSZ)
	copy(tcgContent.SgnCertifyInfoSig, content.SgnCertifyInfoSig)

	tcgContent.Pad = make([]byte, padSz)
	copy(tcgContent.Pad, padding)

	packedContents, err := PackIDevIDContent(tcgContent)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	digest, validationDigest, err := tpm.HashSequence(signerAttrs, packedContents)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	signature, err := tpm.SignValidate(signerAttrs, digest, validationDigest)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	tcgCSR := TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(tcgCSR.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(tcgCSR.Contents[:], contents)
	binary.BigEndian.PutUint32(tcgCSR.SigSz[:], uint32(len(signature)))
	tcgCSR.CsrContents = *tcgContent
	tcgCSR.Signature = signature

	return tcgCSR, nil
}

// Create the TCG_CSR_IDEVID content structure
func (tpm *TPM2) createIDevIDContent(
	ekCert *x509.Certificate,
	akAttrs *keystore.KeyAttributes,
	idevidAttrs *keystore.KeyAttributes) (*UNPACKED_TCG_IDEVID_CONTENT, error) {

	hashSz, err := ParseHashSize(idevidAttrs.Hash)
	if err != nil {
		return nil, err
	}

	bootEventLog, err := tpm.EventLog()
	if err != nil {
		if os.IsNotExist(err) {
			// /sys/kernel/security/tpm0/binary_bios_measurements: no such file or directory
			// return nil, ErrMissingMeasurementLog

			// Some embedded systems may not have a measurement log or there may be a permission
			// problem. Log the warning and carry on...
			tpm.logger.Warn(ErrMissingMeasurementLog.Error())
		} else {
			return nil, err
		}
	}

	akPublicBytes := akAttrs.TPMAttributes.BPublic.Bytes()
	atCreateTktBytes := akAttrs.TPMAttributes.CreationTicketDigest
	akCertifyInfoBytes := akAttrs.TPMAttributes.CertifyInfo
	akCertifyInfoSignature := akAttrs.TPMAttributes.Signature

	sgnCertifyInfoBytes := idevidAttrs.TPMAttributes.CertifyInfo
	signingPubBytes := idevidAttrs.TPMAttributes.BPublic.Bytes()
	sgnCertifyInfoSig := idevidAttrs.TPMAttributes.Signature

	// Build an unpacked TCG_IDEVID_CONTENT structure that omits
	// the HashSz, PadSz, and Pad fields. They will be populated
	// during the packing operation.
	return &UNPACKED_TCG_IDEVID_CONTENT{
		StructVer:  uint32(0x00000100),
		HashAlgoId: uint32(akAttrs.TPMAttributes.HashAlg),
		HashSz:     uint32(hashSz),
		// Hash of all that follows is placed here
		ProdModelSz:               uint32(len(tpm.config.IDevID.Model)),
		ProdSerialSz:              uint32(len(tpm.config.IDevID.Serial)),
		ProdCaDataSz:              uint32(0),
		BootEvntLogSz:             uint32(len(bootEventLog)),
		EkCertSZ:                  uint32(len(ekCert.Raw)),
		AttestPubSZ:               uint32(len(akPublicBytes)),
		AtCreateTktSZ:             uint32(len(atCreateTktBytes)),
		AtCertifyInfoSZ:           uint32(len(akCertifyInfoBytes)),
		AtCertifyInfoSignatureSZ:  uint32(len(akCertifyInfoSignature)),
		SigningPubSZ:              uint32(len(signingPubBytes)),
		SgnCertifyInfoSZ:          uint32(len(sgnCertifyInfoBytes)),
		SgnCertifyInfoSignatureSZ: uint32(len(sgnCertifyInfoSig)),
		// Payload bytes begin here.
		// All payloads are included as byte arrays (no delimiters)
		// Payload is followed by padSz bytes of random data here to make
		// the structure size a multiple of 16 bytes.
		ProdModel:         []byte(tpm.config.IDevID.Model),
		ProdSerial:        []byte(tpm.config.IDevID.Serial),
		ProdCaData:        nil,
		BootEvntLog:       bootEventLog,
		EkCert:            ekCert.Raw,
		AttestPub:         akPublicBytes,
		AtCreateTkt:       atCreateTktBytes,
		AtCertifyInfo:     akCertifyInfoBytes,
		AtCertifyInfoSig:  akCertifyInfoSignature,
		SigningPub:        signingPubBytes,
		SgnCertifyInfo:    sgnCertifyInfoBytes,
		SgnCertifyInfoSig: sgnCertifyInfoSig,
	}, nil
}

// Packs the TCG-CSR-IDEVID into a big endian binary byte array
func PackIDevIDCSR(csr *TCG_CSR_IDEVID) ([]byte, error) {

	var csrBuf bytes.Buffer

	err := binary.Write(&csrBuf, binary.BigEndian, csr.StructVer)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csrBuf, binary.BigEndian, csr.Contents)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csrBuf, binary.BigEndian, csr.SigSz)
	if err != nil {
		return nil, err
	}

	csrContents, err := PackIDevIDContent(&csr.CsrContents)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&csrBuf, binary.BigEndian, csrContents)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csrBuf, binary.BigEndian, csr.Signature)
	if err != nil {
		return nil, err
	}

	return csrBuf.Bytes(), nil
}

// Packs the TCG_IDEVID_CONTENT structure into a big endian byte array
func PackIDevIDContent(content *TCG_IDEVID_CONTENT) ([]byte, error) {

	var csr bytes.Buffer
	err := binary.Write(&csr, binary.BigEndian, content.StructVer)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.HashAlgoId)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.HashSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdModelSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdSerialSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdCaDataSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.BootEvntLogSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.EkCertSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AttestPubSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCreateTktSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SigningPubSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.PadSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdModel)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdSerial)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdCaData)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.BootEvntLog)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.EkCert)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AttestPub)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCreateTkt)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfo)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfoSig)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SigningPub)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfo)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfoSig)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.Pad)
	if err != nil {
		return nil, err
	}

	return csr.Bytes(), nil
}

// Unmarshalls a fixed size big endian byte array into a uint32
func bytesToUint32(b [4]byte) uint32 {
	return binary.BigEndian.Uint32(b[:])
}

// Unmarshalls a TCG_CSR_IDEVID big endian byte array
func UnmarshalIDevIDCSR(csrBytes []byte) (*TCG_CSR_IDEVID, error) {

	reader := bytes.NewReader(csrBytes)

	var structVer [4]byte
	if err := binary.Read(reader, binary.BigEndian, &structVer); err != nil {
		return nil, err
	}

	var contents [4]byte
	if err := binary.Read(reader, binary.BigEndian, &contents); err != nil {
		return nil, err
	}

	var sigSz [4]byte
	if err := binary.Read(reader, binary.BigEndian, &sigSz); err != nil {
		return nil, err
	}

	csr := TCG_CSR_IDEVID{
		StructVer: structVer,
		Contents:  contents,
		SigSz:     sigSz,
	}

	csrContentBytes := make([]byte, 0)
	if _, err := reader.Read(csrContentBytes); err != nil {
		return nil, err
	}

	csrContents, err := UnpackIDevIDContent(reader)
	if err != nil {
		return nil, err
	}
	csr.CsrContents = *csrContents

	csr.Signature = make([]byte, bytesToUint32(sigSz))
	if _, err := reader.Read(csr.Signature); err != nil {
		return nil, err
	}

	return &csr, nil
}

func UnpackIDevIDContent(reader *bytes.Reader) (*TCG_IDEVID_CONTENT, error) {
	content := &TCG_IDEVID_CONTENT{}

	if err := binary.Read(reader, binary.BigEndian, &content.StructVer); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.HashAlgoId); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.HashSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.ProdModelSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.ProdSerialSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.ProdCaDataSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.BootEvntLogSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.EkCertSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AttestPubSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AtCreateTktSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AtCertifyInfoSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AtCertifyInfoSignatureSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.SigningPubSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.SgnCertifyInfoSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.SgnCertifyInfoSignatureSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.PadSz); err != nil {
		return nil, err
	}

	content.ProdModel = make([]byte, bytesToUint32(content.ProdModelSz))
	if _, err := reader.Read(content.ProdModel); err != nil {
		return nil, err
	}

	content.ProdSerial = make([]byte, bytesToUint32(content.ProdSerialSz))
	if _, err := reader.Read(content.ProdSerial); err != nil {
		return nil, err
	}

	content.ProdCaData = make([]byte, bytesToUint32(content.ProdCaDataSz))
	if _, err := reader.Read(content.ProdCaData); err != nil {
		return nil, err
	}

	content.BootEvntLog = make([]byte, bytesToUint32(content.BootEvntLogSz))
	if _, err := reader.Read(content.BootEvntLog); err != nil {
		return nil, err
	}

	content.EkCert = make([]byte, bytesToUint32(content.EkCertSZ))
	if _, err := reader.Read(content.EkCert); err != nil {
		return nil, err
	}

	content.AttestPub = make([]byte, bytesToUint32(content.AttestPubSZ))
	if _, err := reader.Read(content.AttestPub); err != nil {
		return nil, err
	}

	content.AtCreateTkt = make([]byte, bytesToUint32(content.AtCreateTktSZ))
	if _, err := reader.Read(content.AtCreateTkt); err != nil {
		return nil, err
	}

	content.AtCertifyInfo = make([]byte, bytesToUint32(content.AtCertifyInfoSZ))
	if _, err := reader.Read(content.AtCertifyInfo); err != nil {
		return nil, err
	}

	content.AtCertifyInfoSig = make([]byte, bytesToUint32(content.AtCertifyInfoSignatureSZ))
	if _, err := reader.Read(content.AtCertifyInfoSig); err != nil {
		return nil, err
	}

	content.SigningPub = make([]byte, bytesToUint32(content.SigningPubSZ))
	if _, err := reader.Read(content.SigningPub); err != nil {
		return nil, err
	}

	content.SgnCertifyInfo = make([]byte, bytesToUint32(content.SgnCertifyInfoSZ))
	if _, err := reader.Read(content.SgnCertifyInfo); err != nil {
		return nil, err
	}

	content.SgnCertifyInfoSig = make([]byte, bytesToUint32(content.SgnCertifyInfoSignatureSZ))
	if _, err := reader.Read(content.SgnCertifyInfoSig); err != nil {
		return nil, err
	}

	content.Pad = make([]byte, bytesToUint32(content.PadSz))
	if _, err := reader.Read(content.Pad); err != nil {
		return nil, err
	}

	return content, nil
}

// Unpacks a TCG_CSR_IDEVID big endian byte array
func UnpackIDevIDCSR(
	tcgCSRIDevID *TCG_CSR_IDEVID) (*UNPACKED_TCG_CSR_IDEVID, error) {

	tcgCSR := UNPACKED_TCG_CSR_IDEVID{}

	reader := bytes.NewReader(tcgCSRIDevID.StructVer[:])
	err := binary.Read(reader, binary.BigEndian, &tcgCSR.StructVer)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.Contents[:])
	err = binary.Read(reader, binary.BigEndian, &tcgCSR.Contents)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.SigSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgCSR.SigSz)
	if err != nil {
		return nil, err
	}

	tcgCSR.Signature = make([]byte, tcgCSR.SigSz)
	copy(tcgCSR.Signature, tcgCSRIDevID.Signature)

	tcgContents := UNPACKED_TCG_IDEVID_CONTENT{}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.StructVer[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.StructVer)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.HashAlgoId[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.HashAlgoId)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.HashSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.HashSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.ProdModelSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.ProdModelSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.ProdSerialSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.ProdSerialSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.ProdCaDataSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.ProdCaDataSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.BootEvntLogSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.BootEvntLogSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.EkCertSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.EkCertSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AttestPubSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AttestPubSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AtCreateTktSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AtCreateTktSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AtCertifyInfoSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AtCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AtCertifyInfoSignatureSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AtCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.SigningPubSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.SigningPubSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.SgnCertifyInfoSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.SgnCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.SgnCertifyInfoSignatureSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.SgnCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.PadSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.PadSz)
	if err != nil {
		return nil, err
	}

	tcgContents.ProdModel = make([]byte, tcgContents.ProdModelSz)
	n := copy(tcgContents.ProdModel, tcgCSRIDevID.CsrContents.ProdModel)
	if n != int(tcgContents.ProdModelSz) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.ProdSerial = make([]byte, tcgContents.ProdSerialSz)
	n = copy(tcgContents.ProdSerial, tcgCSRIDevID.CsrContents.ProdSerial)
	if n != int(tcgContents.ProdSerialSz) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.ProdCaData = make([]byte, tcgContents.ProdCaDataSz)
	n = copy(tcgContents.ProdCaData, tcgCSRIDevID.CsrContents.ProdCaData)
	if n != int(tcgContents.ProdCaDataSz) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.BootEvntLog = make([]byte, tcgContents.BootEvntLogSz)
	n = copy(tcgContents.BootEvntLog, tcgCSRIDevID.CsrContents.BootEvntLog)
	if n != int(tcgContents.BootEvntLogSz) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.EkCert = make([]byte, tcgContents.EkCertSZ)
	n = copy(tcgContents.EkCert, tcgCSRIDevID.CsrContents.EkCert)
	if n != int(tcgContents.EkCertSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.AttestPub = make([]byte, tcgContents.AttestPubSZ)
	n = copy(tcgContents.AttestPub, tcgCSRIDevID.CsrContents.AttestPub)
	if n != int(tcgContents.AttestPubSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.AtCreateTkt = make([]byte, tcgContents.AtCreateTktSZ)
	n = copy(tcgContents.AtCreateTkt, tcgCSRIDevID.CsrContents.AtCreateTkt)
	if n != int(tcgContents.AtCreateTktSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.AtCertifyInfo = make([]byte, tcgContents.AtCertifyInfoSZ)
	n = copy(tcgContents.AtCertifyInfo, tcgCSRIDevID.CsrContents.AtCertifyInfo)
	if n != int(tcgContents.AtCertifyInfoSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.AtCertifyInfoSig = make([]byte, tcgContents.AtCertifyInfoSignatureSZ)
	n = copy(tcgContents.AtCertifyInfoSig, tcgCSRIDevID.CsrContents.AtCertifyInfoSig)
	if n != int(tcgContents.AtCertifyInfoSignatureSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.SigningPub = make([]byte, tcgContents.SigningPubSZ)
	n = copy(tcgContents.SigningPub, tcgCSRIDevID.CsrContents.SigningPub)
	if n != int(tcgContents.SigningPubSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.SgnCertifyInfo = make([]byte, tcgContents.SgnCertifyInfoSZ)
	n = copy(tcgContents.SgnCertifyInfo, tcgCSRIDevID.CsrContents.SgnCertifyInfo)
	if n != int(tcgContents.SgnCertifyInfoSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.SgnCertifyInfoSig = make([]byte, tcgContents.SgnCertifyInfoSignatureSZ)
	n = copy(tcgContents.SgnCertifyInfoSig, tcgCSRIDevID.CsrContents.SgnCertifyInfoSig)
	if n != int(tcgContents.SgnCertifyInfoSignatureSZ) {
		return nil, common.ErrCorruptCopy
	}

	tcgContents.Pad = make([]byte, tcgContents.PadSz)
	n = copy(tcgContents.Pad, tcgCSRIDevID.CsrContents.Pad)
	if n != int(tcgContents.PadSz) {
		return nil, common.ErrCorruptCopy
	}

	tcgCSR.CsrContents = tcgContents

	return &tcgCSR, nil
}

// Verifies the TCG-CSR-IDEVID using the Identity Provisioning strategy defined in the
// platform configuration file. If a strategy is not defined, the method defined in
// Section 6.2 - OEM Installation of IAK and IDevID in a Single Pass of the TCG TPM 2.0
// Keys for Device Identity and Attestation specification is used as the default strategy.
func (tpm *TPM2) VerifyTCGCSR(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (*keystore.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {

	enrollmentStrategy := ParseIdentityProvisioningStrategy(tpm.config.IdentityProvisioningStrategy)
	switch enrollmentStrategy {
	case EnrollmentStrategyIAK:
		return tpm.VerifyTCG_CSR_IAK(csr, signatureAlgorithm)
	case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
		return tpm.VerifyTCG_CSR_IDevID(csr, signatureAlgorithm)
	}
	return nil, nil, ErrInvalidEnrollmentStrategy
}

// Extracts the Attestation Public Key from TCG_CSR_IDEVID and performs
// verification per TCG TPM 2.0 Keys for Device Identity and Attestation
// per Section 6.1.2 - Procedure for OEM Creation of an IAK Certificate.
// 5. The CA verifies the received data:
// a. Verify the signature on the TCG-CSR-IDEVID:
// i. Extract the IAK Public Key from the IAK Public Area in the TCG-CSR-IDEVID.
// ii. Use the IAK public key to verify the signature on the TCG-CSR-IDEVID.
// b. Extract the EK certificate from the TCG-CSR-IDEVID and verify the EK
// Certificate using the indicated TPM manufacturer’s public key.
// c. Verify the attributes (TPMA_OBJECT bits) of the IAK Public Area to ensure
// that the key is a Restricted, fixedTPM, fixedParent signing key. Ensure all
// other attributes meet CA policy.
// NOTE: Step b is not implemented here. The EK certificate should be verified by
// the CA package using the Verify(certificate *x509.Certificate) method.
func (tpm *TPM2) VerifyTCG_CSR_IAK(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (*keystore.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, nil, err
	}

	// Unpack CSR to UNPACKED_TCG_CSR_IDEVID
	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		return nil, nil, err
	}

	// Set the TCG and crypto hash algorithm
	hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId)
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, nil, err
	}

	// Load the AK public area
	loadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](
			unpacked.CsrContents.AttestPub),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Flush(loadRsp.ObjectHandle)

	// Load default TPM attributes for the AK
	keyAttrs, err := tpm.KeyAttributes(loadRsp.ObjectHandle)
	if err != nil {
		return nil, nil, err
	}
	keyAttrs.Parent = ekAttrs
	keyAttrs.SignatureAlgorithm = signatureAlgorithm
	keyAttrs.StoreType = keystore.STORE_TPM2
	keyAttrs.TPMAttributes.HashAlg = hashAlgo

	// Set the key algorithm
	if keystore.IsECDSA(signatureAlgorithm) {
		keyAttrs.KeyAlgorithm = x509.ECDSA
	} else {
		keyAttrs.KeyAlgorithm = x509.RSA
	}

	pub := keyAttrs.TPMAttributes.Public

	// Ensure the AK is a Restricted, fixedTPM, fixedParent signing key
	if !pub.ObjectAttributes.Restricted {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !pub.ObjectAttributes.FixedTPM {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !pub.ObjectAttributes.FixedParent {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !pub.ObjectAttributes.SignEncrypt {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}

	// Verify the CSR using the IAK public key
	if err := tpm.verifyTCGCSRSignature(csr, hash, keyAttrs); err != nil {
		return nil, nil, err
	}

	return keyAttrs, unpacked, nil
}

// Extracts the Attestation Public Key from TCG_CSR_IDEVID and performs
// verification per TCG TPM 2.0 Keys for Device Identity and Attestation
// per Section 6.2.2 - Procedure for OEM Installation of IAK and IDevID
// in a Single Pass.
// 7. The CA verifies the received data:
// a. Extract IDevID public key and verify the signature on TCG-CSR-IDEVID
// b. Verify the EK Certificate using the indicated TPM manufacturer’s public key
// c. Verify TPM residency of IDevID key using the IAK public key to validate the signature of the
// TPMB_Attest structure.
// d. Verify the attributes of the IDevID key public area.
// e. Verify the attributes of the IAK public area.
// f. Calculate the Name of the IAK, by hashing its public area with its associated hash algorithm,
// prepended with the Algorithm ID of the hashing algorithm. Refer to TPM 2.0 Library Specification [2]
// Part 1, Section 16, “Names”.
// g. Using the sequence described in the TPM 2.0 Library Specification [2] Part 3, section 12.6.3
// (TPM2_MakeCredential Detailed Actions), create the encrypted “credential” structure to be sent to
// the device. When building this encrypted structure, objectName is the Name of the IAK calculated in
// step ‘a’ and Certificate (which is the payload field) holds a nonce (whose size matches the Name
// hash). Retain the nonce for use in later steps.
// NOTE: Step b is not implemented here. The EK certificate should be verified by
// the CA package using the Verify(certificate *x509.Certificate) method.
func (tpm *TPM2) VerifyTCG_CSR_IDevID(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (*keystore.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, nil, err
	}

	// Unpack CSR to UNPACKED_TCG_CSR_IDEVID
	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		return nil, nil, err
	}

	// // Set the TCG and crypto hash algorithm
	hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId)
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, nil, err
	}

	// Load the IAK public area
	iakLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](
			unpacked.CsrContents.AttestPub),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}

	// Load default TPM attributes for the IAK
	iakAttrs, err := tpm.KeyAttributes(iakLoadRsp.ObjectHandle)
	if err != nil {
		return nil, nil, err
	}

	tpm.Flush(iakLoadRsp.ObjectHandle)

	iakPub := iakAttrs.TPMAttributes.Public

	// Ensure the AK is a Restricted, fixedTPM, fixedParent signing key
	if !iakPub.ObjectAttributes.Restricted {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !iakPub.ObjectAttributes.FixedTPM {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !iakPub.ObjectAttributes.FixedParent {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !iakPub.ObjectAttributes.SignEncrypt {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}

	// Load the IDevID public area
	idevidLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](
			unpacked.CsrContents.SigningPub),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}

	// Load default TPM attributes for the IDevID
	idevidAttrs, err := tpm.KeyAttributes(idevidLoadRsp.ObjectHandle)
	if err != nil {
		return nil, nil, err
	}

	tpm.Flush(idevidLoadRsp.ObjectHandle)

	idevidAttrs.Parent = ekAttrs
	idevidAttrs.SignatureAlgorithm = signatureAlgorithm
	idevidAttrs.StoreType = keystore.STORE_TPM2
	idevidAttrs.TPMAttributes.HashAlg = hashAlgo

	idevidPub := idevidAttrs.TPMAttributes.Public

	// Ensure the IDevID is an Unrestricted, fixedTPM, fixedParent signing key
	if idevidPub.ObjectAttributes.Restricted {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !idevidPub.ObjectAttributes.FixedTPM {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !idevidPub.ObjectAttributes.FixedParent {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}
	if !idevidPub.ObjectAttributes.SignEncrypt {
		return nil, nil, keystore.ErrInvalidKeyAttributes
	}

	// Set the signing key algorithm
	if keystore.IsECDSA(signatureAlgorithm) {
		idevidAttrs.KeyAlgorithm = x509.ECDSA
	} else {
		idevidAttrs.KeyAlgorithm = x509.RSA
	}

	// Verify the CSR using the IDevID public key
	if err := tpm.verifyTCGCSRSignature(csr, hash, idevidAttrs); err != nil {
		return nil, nil, err
	}

	return idevidAttrs, unpacked, nil
}

// Verifies the TCG-CSR-IDEVID signature using the provided hash and key attributes
func (tpm *TPM2) verifyTCGCSRSignature(
	csr *TCG_CSR_IDEVID,
	hash crypto.Hash,
	keyAttrs *keystore.KeyAttributes) error {

	pub := keyAttrs.TPMAttributes.Public

	// Re-pack the CSR contents to get the digest
	packedContents, err := PackIDevIDContent(&csr.CsrContents)
	if err != nil {
		return err
	}

	// Perform hash sequence on the (large) digest
	digest, _, err := tpm.HashSequence(keyAttrs, packedContents)
	if err != nil {
		return err
	}

	// Verify the TCG-CSR-IDEVID signature
	if pub.Type == tpm2.TPMAlgRSA {

		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return err
		}

		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return err
		}

		if keystore.IsRSAPSS(keyAttrs.SignatureAlgorithm) {

			// RSA PSS
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			}
			err = rsa.VerifyPSS(
				rsaPub, hash, digest, csr.Signature, pssOpts)
			if err != nil {
				return ErrInvalidSignature
			}

			// _, err = tpm2.VerifySignature{
			// 	KeyHandle: keyAttrs.TPMAttributes.Handle,
			// 	Digest: tpm2.TPM2BDigest{
			// 		Buffer: digest,
			// 	},
			// 	Signature: tpm2.TPMTSignature{
			// 		SigAlg: tpm2.TPMAlgRSAPSS,
			// 		Signature: tpm2.NewTPMUSignature[*tpm2.TPMSSignatureRSA](
			// 			tpm2.TPMAlgRSAPSS,
			// 			&tpm2.TPMSSignatureRSA{
			// 				Hash: keyAttrs.TPMAttributes.HashAlg,
			// 				Sig: tpm2.TPM2BPublicKeyRSA{
			// 					Buffer: csr.Signature,
			// 				},
			// 			},
			// 		),
			// 	},
			// }.Execute(tpm.transport)
			// if err != nil {
			// 	tpm.logger.Error(err)
			// 	return nil, nil, err
			// }

		} else {

			err = rsa.VerifyPKCS1v15(rsaPub, hash, digest, csr.Signature)
			if err != nil {
				return ErrInvalidSignature
			}

			// _, err = tpm2.VerifySignature{
			// 	KeyHandle: keyAttrs.TPMAttributes.Handle,
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
			// 					Buffer: csr.Signature,
			// 				},
			// 			},
			// 		),
			// 	},
			// }.Execute(tpm.transport)
			// if err != nil {
			// 	return nil, nil, err
			// }
		}

	} else if pub.Type == tpm2.TPMAlgECC {

		ecDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return err
		}

		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return err
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return err
		}

		ecdsaPub := &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

		if !ecdsa.VerifyASN1(ecdsaPub, digest, csr.Signature) {
			return ErrInvalidSignature
		}
	}

	return nil
}
