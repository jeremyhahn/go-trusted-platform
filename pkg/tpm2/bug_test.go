package tpm2

// import (
// 	"crypto"
// 	"crypto/rand"
// 	"crypto/rsa"
// 	"crypto/sha256"
// 	"testing"

// 	"github.com/google/go-cmp/cmp"
// 	"github.com/google/go-tpm-tools/simulator"
// 	"github.com/google/go-tpm/tpm2"
// 	"github.com/google/go-tpm/tpm2/transport"

// 	// "github.com/google/go-tpm/tpm2/transport/simulator"
// 	"github.com/stretchr/testify/assert"
// )

// func TestBug(t *testing.T) {

// 	// thetpm, err := simulator.OpenSimulator()
// 	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
// 	if err != nil {
// 		t.Fatalf("could not connect to TPM simulator: %v", err)
// 	}
// 	// defer thetpm.Close()
// 	thetpm := transport.FromReadWriter(sim)

// 	// Set hierarchy auth
// 	hierarchies := []tpm2.TPMHandle{
// 		tpm2.TPMRHEndorsement,
// 		tpm2.TPMRHLockout,
// 		tpm2.TPMRHOwner,
// 	}
// 	for _, hierarchy := range hierarchies {
// 		_, err := tpm2.HierarchyChangeAuth{
// 			AuthHandle: tpm2.AuthHandle{
// 				Handle: hierarchy,
// 				Auth:   tpm2.PasswordAuth(nil),
// 			},
// 			NewAuth: tpm2.TPM2BAuth{
// 				Buffer: []byte{},
// 			},
// 		}.Execute(thetpm)
// 		assert.Nil(t, err)
// 	}

// 	Auth := []byte(nil)

// 	public := tpm2.New2B(tpm2.TPMTPublic{
// 		Type:    tpm2.TPMAlgRSA,
// 		NameAlg: tpm2.TPMAlgSHA256,
// 		ObjectAttributes: tpm2.TPMAObject{
// 			SignEncrypt:         true,
// 			Restricted:          true,
// 			FixedTPM:            true,
// 			FixedParent:         true,
// 			SensitiveDataOrigin: true,
// 			UserWithAuth:        true,
// 		},
// 		Parameters: tpm2.NewTPMUPublicParms(
// 			tpm2.TPMAlgRSA,
// 			&tpm2.TPMSRSAParms{
// 				Scheme: tpm2.TPMTRSAScheme{
// 					Scheme: tpm2.TPMAlgRSASSA,
// 					Details: tpm2.NewTPMUAsymScheme(
// 						tpm2.TPMAlgRSASSA,
// 						&tpm2.TPMSSigSchemeRSASSA{
// 							HashAlg: tpm2.TPMAlgSHA256,
// 						},
// 					),
// 				},
// 				KeyBits: 2048,
// 			},
// 		),
// 		Unique: tpm2.NewTPMUPublicID(
// 			tpm2.TPMAlgRSA,
// 			&tpm2.TPM2BPublicKeyRSA{
// 				Buffer: make([]byte, 256),
// 			},
// 		),
// 	},
// 	)

// 	pcrSelection := tpm2.TPMLPCRSelection{
// 		PCRSelections: []tpm2.TPMSPCRSelection{
// 			{
// 				Hash:      tpm2.TPMAlgSHA256,
// 				PCRSelect: tpm2.PCClientCompatible.PCRs(16),
// 			},
// 		},
// 	}

// 	// Create AK
// 	createPrimarySigner := tpm2.CreatePrimary{
// 		PrimaryHandle: tpm2.TPMRHEndorsement,
// 		InSensitive: tpm2.TPM2BSensitiveCreate{
// 			Sensitive: &tpm2.TPMSSensitiveCreate{
// 				UserAuth: tpm2.TPM2BAuth{
// 					Buffer: Auth,
// 				},
// 			},
// 		},
// 		InPublic:    public,
// 		CreationPCR: pcrSelection,
// 	}
// 	rspSigner, err := createPrimarySigner.Execute(thetpm)
// 	if err != nil {
// 		t.Fatalf("Failed to create primary: %v", err)
// 	}

// 	iakPub, err := rspSigner.OutPublic.Contents()
// 	assert.Nil(t, err)

// 	rsaDetails, err := iakPub.Parameters.RSADetail()
// 	assert.Nil(t, err)

// 	// Certify the new IAK primary key
// 	certifyCreation := tpm2.CertifyCreation{
// 		SignHandle: tpm2.AuthHandle{
// 			Handle: rspSigner.ObjectHandle,
// 			Name:   rspSigner.Name,
// 			Auth:   tpm2.PasswordAuth(Auth),
// 		},
// 		ObjectHandle: tpm2.NamedHandle{
// 			Handle: rspSigner.ObjectHandle,
// 			Name:   rspSigner.Name,
// 		},
// 		CreationHash: rspSigner.CreationHash,
// 		InScheme: tpm2.TPMTSigScheme{
// 			Scheme: rsaDetails.Scheme.Scheme,
// 			Details: tpm2.NewTPMUSigScheme(
// 				rsaDetails.Scheme.Scheme, &tpm2.TPMSSchemeHash{
// 					HashAlg: tpm2.TPMAlgSHA256,
// 				}),
// 		},
// 		CreationTicket: rspSigner.CreationTicket,
// 	}
// 	_, err = certifyCreation.Execute(thetpm)
// 	assert.Nil(t, err)

// 	// Create subject
// 	createPrimarySubject := tpm2.CreatePrimary{
// 		PrimaryHandle: tpm2.TPMRHEndorsement,
// 		InSensitive: tpm2.TPM2BSensitiveCreate{
// 			Sensitive: &tpm2.TPMSSensitiveCreate{
// 				UserAuth: tpm2.TPM2BAuth{
// 					Buffer: Auth,
// 				},
// 			},
// 		},
// 		InPublic:    public,
// 		CreationPCR: pcrSelection,
// 	}
// 	unique := tpm2.NewTPMUPublicID(
// 		tpm2.TPMAlgRSA,
// 		&tpm2.TPM2BPublicKeyRSA{
// 			Buffer: []byte("subject key"),
// 		},
// 	)
// 	inPub, err := createPrimarySubject.InPublic.Contents()
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// 	inPub.Unique = unique

// 	rspSubject, err := createPrimarySubject.Execute(thetpm)
// 	if err != nil {
// 		t.Fatalf("Failed to create primary: %v", err)
// 	}

// 	// Certify
// 	originalBuffer := []byte("test nonce")

// 	certify := tpm2.Certify{
// 		ObjectHandle: tpm2.AuthHandle{
// 			Handle: rspSubject.ObjectHandle,
// 			Name:   rspSubject.Name,
// 			Auth:   tpm2.PasswordAuth(Auth),
// 		},
// 		SignHandle: tpm2.AuthHandle{
// 			Handle: rspSigner.ObjectHandle,
// 			Name:   rspSigner.Name,
// 			Auth:   tpm2.PasswordAuth(Auth),
// 		},
// 		QualifyingData: tpm2.TPM2BData{
// 			Buffer: originalBuffer,
// 		},
// 		InScheme: tpm2.TPMTSigScheme{
// 			Scheme: tpm2.TPMAlgNull,
// 		},
// 	}

// 	rspCert, err := certify.Execute(thetpm)
// 	if err != nil {
// 		t.Fatalf("Failed to certify: %v", err)
// 	}

// 	// Extract certification info
// 	certifyInfo, err := rspCert.CertifyInfo.Contents()
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// 	info := tpm2.Marshal(certifyInfo)
// 	attestHash := sha256.Sum256(info)

// 	// Extract public area and RSA key
// 	pub, err := rspSigner.OutPublic.Contents()
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// 	rsaDetail, err := pub.Parameters.RSADetail()
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// 	rsaUnique, err := pub.Unique.RSA()
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// 	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// 	rsassa, err := rspCert.Signature.Signature.RSASSA()
// 	if err != nil {
// 		t.Fatalf("%v", err)
// 	}
// 	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, attestHash[:], rsassa.Sig.Buffer); err != nil {
// 		t.Errorf("Signature verification failed: %v", err)
// 	}
// 	if !cmp.Equal(originalBuffer, certifyInfo.ExtraData.Buffer) {
// 		t.Errorf("Attested buffer is different from original buffer")
// 	}

// 	// Hash some data
// 	// data := []byte("some test data")

// 	// hashRsp, err := tpm2.Hash{
// 	// 	HashAlg:   tpm2.TPMAlgSHA256,
// 	// 	Hierarchy: tpm2.TPMRHEndorsement,
// 	// 	Data: tpm2.TPM2BMaxBuffer{
// 	// 		Buffer: data,
// 	// 	},
// 	// }.Execute(thetpm)

// 	// Hash large amount of data using sequence
// 	data := make([]byte, 50000)
// 	rand.Reader.Read(data)

// 	var maxDigestBuffer = 1024

// 	hasher := crypto.SHA256.New()
// 	hasher.Reset()

// 	hashSequenceStart := tpm2.HashSequenceStart{
// 		Auth: tpm2.TPM2BAuth{
// 			Buffer: Auth,
// 		},
// 		HashAlg: tpm2.TPMAlgSHA256,
// 	}
// 	rspHSS, err := hashSequenceStart.Execute(thetpm)
// 	assert.Nil(t, err)

// 	authHandle := tpm2.AuthHandle{
// 		Handle: rspHSS.SequenceHandle,
// 		Name: tpm2.TPM2BName{
// 			Buffer: Auth,
// 		},
// 		Auth: tpm2.PasswordAuth(Auth),
// 	}

// 	for len(data) > maxDigestBuffer {
// 		sequenceUpdate := tpm2.SequenceUpdate{
// 			SequenceHandle: authHandle,
// 			Buffer: tpm2.TPM2BMaxBuffer{
// 				Buffer: data[:maxDigestBuffer],
// 			},
// 		}
// 		_, err = sequenceUpdate.Execute(thetpm)
// 		assert.Nil(t, err)

// 		hasher.Sum(data[:maxDigestBuffer])

// 		data = data[maxDigestBuffer:]
// 	}

// 	sequenceComplete := tpm2.SequenceComplete{
// 		SequenceHandle: authHandle,
// 		Buffer: tpm2.TPM2BMaxBuffer{
// 			Buffer: data,
// 		},
// 		Hierarchy: tpm2.TPMRHEndorsement,
// 	}

// 	rspSC, err := sequenceComplete.Execute(thetpm)
// 	assert.Nil(t, err)

// 	// Set the data and validation digest
// 	digest := rspSC.Result.Buffer
// 	validationDigest := rspSC.Validation.Digest.Buffer

// 	// digest := hashRsp.OutHash.Buffer

// 	// Quick sanity check
// 	// expected := sha256.Sum256(data)
// 	// expectedDigest := expected[:]
// 	// assert.Equal(t, expectedDigest, digest)

// 	// Sign the digest
// 	signRsp, err := tpm2.Sign{
// 		KeyHandle: tpm2.AuthHandle{
// 			Handle: rspSigner.ObjectHandle,
// 			Name:   rspSigner.Name,
// 			Auth:   tpm2.PasswordAuth(nil),
// 		},
// 		Digest: tpm2.TPM2BDigest{
// 			Buffer: digest,
// 		},
// 		InScheme: tpm2.TPMTSigScheme{
// 			Scheme: rsaDetail.Scheme.Scheme,
// 			Details: tpm2.NewTPMUSigScheme(
// 				rsaDetail.Scheme.Scheme, &tpm2.TPMSSchemeHash{
// 					HashAlg: tpm2.TPMAlgSHA256,
// 				}),
// 		},
// 		Validation: tpm2.TPMTTKHashCheck{
// 			Hierarchy: tpm2.TPMRHEndorsement,
// 			Digest: tpm2.TPM2BDigest{
// 				Buffer: validationDigest,
// 			},
// 			Tag: tpm2.TPMSTHashCheck,
// 		},
// 	}.Execute(thetpm)
// 	assert.Nil(t, err)

// 	rsaSig, err := signRsp.Signature.Signature.RSASSA()
// 	assert.Nil(t, err)

// 	signature := rsaSig.Sig.Buffer

// 	// Verify the signature
// 	_, err = tpm2.VerifySignature{
// 		KeyHandle: rspSigner.ObjectHandle,
// 		Digest: tpm2.TPM2BDigest{
// 			Buffer: digest,
// 		},
// 		Signature: tpm2.TPMTSignature{
// 			SigAlg: tpm2.TPMAlgRSASSA,
// 			Signature: tpm2.NewTPMUSignature[*tpm2.TPMSSignatureRSA](
// 				tpm2.TPMAlgRSASSA,
// 				&tpm2.TPMSSignatureRSA{
// 					Hash: tpm2.TPMAlgSHA256,
// 					Sig: tpm2.TPM2BPublicKeyRSA{
// 						Buffer: signature,
// 					},
// 				},
// 			),
// 		},
// 	}.Execute(thetpm)
// 	assert.Nil(t, err)

// 	// Now flush the handles and verify using loaded handle...
// 	tpm2.FlushContext{FlushHandle: rspSigner.ObjectHandle}.Execute(thetpm)
// 	tpm2.FlushContext{FlushHandle: rspSubject.ObjectHandle}.Execute(thetpm)

// 	// Load external
// 	loadRsp, err := tpm2.LoadExternal{
// 		Hierarchy: tpm2.TPMRHEndorsement,
// 		InPublic:  tpm2.New2B(*pub),
// 	}.Execute(thetpm)
// 	assert.Nil(t, err)

// 	_, err = tpm2.VerifySignature{
// 		KeyHandle: loadRsp.ObjectHandle,
// 		Digest: tpm2.TPM2BDigest{
// 			Buffer: digest,
// 		},
// 		Signature: tpm2.TPMTSignature{
// 			SigAlg: tpm2.TPMAlgRSASSA,
// 			Signature: tpm2.NewTPMUSignature[*tpm2.TPMSSignatureRSA](
// 				tpm2.TPMAlgRSASSA,
// 				&tpm2.TPMSSignatureRSA{
// 					Hash: tpm2.TPMAlgSHA256,
// 					Sig: tpm2.TPM2BPublicKeyRSA{
// 						Buffer: signature,
// 					},
// 				},
// 			),
// 		},
// 	}.Execute(thetpm)
// 	assert.Nil(t, err)

// 	// Flush the loaded handle and try again, should fail
// 	tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(thetpm)
// 	_, err = tpm2.VerifySignature{
// 		KeyHandle: loadRsp.ObjectHandle,
// 		Digest: tpm2.TPM2BDigest{
// 			Buffer: digest,
// 		},
// 		Signature: tpm2.TPMTSignature{
// 			SigAlg: tpm2.TPMAlgRSASSA,
// 			Signature: tpm2.NewTPMUSignature[*tpm2.TPMSSignatureRSA](
// 				tpm2.TPMAlgRSASSA,
// 				&tpm2.TPMSSignatureRSA{
// 					Hash: tpm2.TPMAlgSHA256,
// 					Sig: tpm2.TPM2BPublicKeyRSA{
// 						Buffer: signature,
// 					},
// 				},
// 			),
// 		},
// 	}.Execute(thetpm)
// 	assert.NotNil(t, err)

// 	// Load again and verify again
// 	loadRsp, err = tpm2.LoadExternal{
// 		Hierarchy: tpm2.TPMRHEndorsement,
// 		InPublic:  tpm2.New2B(*pub),
// 	}.Execute(thetpm)
// 	assert.Nil(t, err)

// 	_, err = tpm2.VerifySignature{
// 		KeyHandle: loadRsp.ObjectHandle,
// 		Digest: tpm2.TPM2BDigest{
// 			Buffer: digest,
// 		},
// 		Signature: tpm2.TPMTSignature{
// 			SigAlg: tpm2.TPMAlgRSASSA,
// 			Signature: tpm2.NewTPMUSignature[*tpm2.TPMSSignatureRSA](
// 				tpm2.TPMAlgRSASSA,
// 				&tpm2.TPMSSignatureRSA{
// 					Hash: tpm2.TPMAlgSHA256,
// 					Sig: tpm2.TPM2BPublicKeyRSA{
// 						Buffer: signature,
// 					},
// 				},
// 			),
// 		},
// 	}.Execute(thetpm)
// 	assert.Nil(t, err)
// }
