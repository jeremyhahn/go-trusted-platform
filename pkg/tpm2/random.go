package tpm2

import "github.com/google/go-tpm/tpm2"

// Reads random bytes from the TPM into the data buffer. Optionally
// uses the EK to encrypt the session between the CPU <-> TPM if
// session encryption is enabled in the platform configuration file.
// If the TPM Endorsement Hierarchy authorization has an authorization
// password set, and the EK has not been made persistent, the
// tpm.hierarchyAuth property must be set before reading so a transient
// EK can be created (under the Endorsement Hierarchy) to encrypt the
// session. The hierarchy auth is automatically set during provisioning
// - ie, when Provision() is called. After provisioning is complete,
// subsequent platform startups will have to explicitly provide the hierarchy
// password, since it's never saved, loaded, or cached during normal operation.
// The hierarchy password is only cached in memory during provisioning and
// wiped from memory when the program exits.
func (tpm *TPM2) Read(data []byte) (n int, err error) {

	var result []byte
	var sess tpm2.Session

	if tpm.config.EncryptSession {

		// tpm.logger.Debugf("tpm: (encrypted TPM <-> CPU) reading %d byte(s)", len(data))
		ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
		response, err := tpm2.ReadPublic{
			ObjectHandle: ekHandle,
		}.Execute(tpm.transport)
		if err != nil {

			tpm.logger.Warning(err)

			ekAttrs, err := tpm.EKAttributes()
			if err != nil {
				return 0, err
			}
			sess = tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.AESEncryption(
					128,
					tpm2.EncryptOut),
				tpm2.Salted(ekAttrs.TPMAttributes.Handle, ekAttrs.TPMAttributes.Public))

		} else {

			// Use the persistent EK handle to encrypt the session
			ekPub, err := response.OutPublic.Contents()
			if err != nil {
				tpm.logger.Error(err)
				return 0, err
			}
			sess = tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.AESEncryption(
					128,
					tpm2.EncryptOut),
				tpm2.Salted(ekHandle, *ekPub))
		}

	} else {
		// No key available to salt the connection
		sess = tpm2.HMAC(
			tpm2.TPMAlgSHA256,
			16,
			tpm2.AESEncryption(128, tpm2.EncryptOut))
	}

	// Get the random bytes
	resp, err := tpm2.GetRandom{
		BytesRequested: uint16(len(data)),
	}.Execute(tpm.Transport(), sess)
	if err != nil {
		tpm.logger.Error(err)
		return 0, err
	}

	result = resp.RandomBytes.Buffer
	copy(data, resp.RandomBytes.Buffer)

	return len(result), nil
}

// Reads a random 32 byte fixed length slice from RNG
func (tpm *TPM2) Random() ([]byte, error) {

	var err error
	var n int
	fixedLength := 32
	bytes := make([]byte, fixedLength)

	// Read fixed length bytes
	n, err = tpm.Read(bytes)
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

// Reads a random fixed length byte slice from RNG
func (tpm *TPM2) RandomBytes(fixedLength int) ([]byte, error) {

	var err error
	var n int
	bytes := make([]byte, fixedLength)

	// Read fixed length bytes
	n, err = tpm.Read(bytes)
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

// Reads a random fixed length byte slice from RNG and
// returns the resulting bytes encoded in hexidecimal format.
func (tpm *TPM2) RandomHex(fixedLength int) ([]byte, error) {

	var err error
	var n int
	len := fixedLength / 2
	bytes := make([]byte, len)

	// Read fixed length bytes
	n, err = tpm.Read(bytes)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, ErrUnexpectedRandomBytes
	}
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	tpm.logger.Debugf("tpm: read %d random bytes", n)

	return []byte(Encode(bytes)), nil
}
