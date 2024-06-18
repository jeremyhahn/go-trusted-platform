package tpm2

import (
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

func TestRandBytes(t *testing.T) {
	tpm, err := simulator.Get()
	require.NoError(t, err)
	defer tpm.Close()

	randomBytes := make([]byte, 32)

	rwr := transport.FromReadWriter(tpm)
	reader := NewRandomReader(rwr)

	i, err := reader.Read(randomBytes)
	require.NoError(t, err)
	require.Equal(t, len(randomBytes), i)
	require.Equal(t, len(randomBytes), 32)
}

func TestRandBytesEncrypted(t *testing.T) {
	tpm, err := simulator.Get()
	require.NoError(t, err)
	defer tpm.Close()

	rwr := transport.FromReadWriter(tpm)
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}
	createEKRsp, err := createEKCmd.Execute(rwr)
	require.NoError(t, err)

	encryptionPub, err := createEKRsp.OutPublic.Contents()
	require.NoError(t, err)

	randomBytes := make([]byte, 32)
	reader := NewRandomReader(rwr)
	require.NoError(t, err)

	reader.EncryptionHandle = createEKRsp.ObjectHandle
	reader.EncryptionPub = encryptionPub

	_, err = reader.Read(randomBytes)
	require.NoError(t, err)

	require.Equal(t, len(randomBytes), 32)
}

func TestRSAKey(t *testing.T) {
	tpm, err := simulator.Get()
	require.NoError(t, err)
	defer tpm.Close()

	rwr := transport.FromReadWriter(tpm)
	reader := NewRandomReader(rwr)

	require.NoError(t, err)

	// RSA keygen
	privkey, err := rsa.GenerateKey(reader, 2048)
	require.NoError(t, err)

	rsaPubKey := privkey.PublicKey
	require.Equal(t, 2048, rsaPubKey.Size()*8)
}
