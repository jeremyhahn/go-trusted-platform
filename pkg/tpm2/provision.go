package tpm2

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// Clears the TPM as described in TCG Part 3: Commands - Section 24.6 - TPM2_Clear
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
func (tpm *TPM2) Clear(hierarchyAuth []byte, hierarchy tpm2.TPMHandle) error {
	_, err := tpm2.Clear{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
	}.Execute(tpm.transport)
	if err != nil {
		return err
	}
	return nil
}

// Install performs a safe, modified version of the TCG recommended provisioning
// guidance intended for platforms that have already been minimally provisioned
// by the TPM Manufacturer or Owner. Instead of clearing the hierarchies,
// setting hierarchy authorizations and provisioning new keys and certificates
// from scratch, this method will use pre-existing EK and SRK keys and
// certificates if they already exist. The provided soPIN parameter is used
// as the new Endorsement and Storage hierarchy authorizations during installation.
// The current hierarchy authorization is expected to be set to an empty password.
// You can use the included CLI or TPM2 tools to execute the TPM2_HierarchyChangeAuth
// command to set the password to an empty password.
func (tpm *TPM2) Install(soPIN keystore.Password) error {

	tpm.logger.Info("Installing Platform")

	// Set new hierarchy authorizations
	if err := tpm.SetHierarchyAuth(nil, soPIN, nil); err != nil {
		return err
	}

	// Create EK if it doesnt exist
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		if err == tpm2.TPMRC(0x18b) {
			// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
			tpm.logger.Info("Creating Endorsement Key")
			ekAttrs, err = EKAttributesFromConfig(*tpm.config.EK, &tpm.policyDigest)
			if err != nil {
				return err
			}
			ekAttrs.TPMAttributes.HierarchyAuth = soPIN
			if err := tpm.CreateEK(ekAttrs); err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		ekAttrs.TPMAttributes.HierarchyAuth = soPIN
	}

	// Create SSRK if it doesnt exist
	ssrkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		if err == tpm2.TPMRC(0x18b) {
			tpm.logger.Info("Creating Shared SRK")
			ssrkAttrs, err = SRKAttributesFromConfig(*tpm.config.SSRK, &tpm.policyDigest)
			if err != nil {
				return err
			}
			ssrkAttrs.Parent = ekAttrs
			ssrkAttrs.TPMAttributes.HierarchyAuth = soPIN
			if err := tpm.CreateSRK(ssrkAttrs); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Capture platform measurements and create the policy digest
	if err := tpm.CreatePlatformPolicy(); err != nil {
		return err
	}

	// Create IAK if it doesnt exist
	if _, err = tpm.IAKAttributes(); err == ErrNotInitialized {
		tpm.logger.Info("Creating Initial Attesation Key")
		if _, err := tpm.CreateIAK(ekAttrs); err != nil {
			return err
		}
	}

	// Retrieve the EK certificate or return an error
	if _, err := tpm.EKCertificate(); err != nil {
		return err
	}

	// Platform is provisioned
	return nil
}

// Provision the TPM as outlined in the TCG Provisioning Guidance -
// Section 11.1 - Provisioning the TPM.
// - Clear the TPM
// - Set Endorsement, Owner and Lockout authorizations
// - Create, verify & persist EK
// - Create, verify & persist IDevID
// - Create Initial Device Identity for touch-free provisioning
// - Create, & persist Shared SRK
// - Establish baseline PCRs
// - Capture Golden Integrity Measurements
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
//
// This operation requires hierarchy authorization to perform the TPM2_Clear
// command as the first step outlined in the TCG Provisioning Guidance, and
// assumes the auth parameter for these hierarchies to be set to an empty password.
// The TPM2_ChangeAuth command may be used prior to invoking this operation to set
// the hierarchy passwords to an empty value so this operation may complete.
// After this operation clears the TPM, the provided Security Officer PIN is used
// to set new Lockout, Endorsement and Owner authorization values. When this
// operation completes, the Lockout, Endorsement and Owner hierarchies are all
// owned by the Security Officer, the TPM is fully provisioned and ready for use.
// The hierarchy authorization values assigned during this operation may be safely
// modified to use authorization passwords and/or policies to align the platform
// with Enterprise or Platform Administrator requirements following this provisioning
// process.
func (tpm *TPM2) Provision(soPIN keystore.Password) error {

	tpm.logger.Info("Provisioning New Platform")

	tpm.logger.Info("Clearing TPM Endorsement and Owner Hierarchies")
	// Clear endorsement and owner hierarchies
	if err := tpm.Clear(nil, tpm2.TPMRHEndorsement); err != nil {
		tpm.logger.Warning("tpm: failed to clear Endorsement hierarchy")
		tpm.logger.Warning(err)
		//return nil, err
	}
	if err := tpm.Clear(nil, tpm2.TPMRHOwner); err != nil {
		tpm.logger.Warning("tpm: failed to clear Owner hierarchy")
		tpm.logger.Warning(err)
		// return nil, err
	}

	tpm.logger.Info("Setting new Lockout, Endorsement and Owner Hierarchy Authorizations")
	lockoutHierarchy := tpm2.TPMRHLockout
	err := tpm.SetHierarchyAuth(nil, soPIN, &lockoutHierarchy)
	if err != nil {
		return err
	}
	endorsementHierarchy := tpm2.TPMRHEndorsement
	err = tpm.SetHierarchyAuth(nil, soPIN, &endorsementHierarchy)
	if err != nil {
		return err
	}
	ownerHierarchy := tpm2.TPMRHOwner
	err = tpm.SetHierarchyAuth(nil, soPIN, &ownerHierarchy)
	if err != nil {
		return err
	}

	if tpm.debugSecrets {
		var soPinBytes []byte
		var err error
		if soPIN != nil {
			soPinBytes, err = soPIN.Bytes()
			if err != nil {
				return err
			}
		}
		tpm.logger.Debugf("tpm: Lockout, Endorsement & Storage Hierarchy authorization: %s", soPinBytes)
	}

	// Provision Owner hierarchy with new EK and SRK
	srkAttrs, err := tpm.ProvisionOwner(soPIN)
	if err != nil {
		if err == tpm2.TPMRC(0x14c) {
			// TPM_RC_NV_DEFINED: NV Index or persistent object already defined
			return keystore.ErrAlreadyInitialized
		}
		return err
	}

	// Create platform policy digest
	if err := tpm.CreatePlatformPolicy(); err != nil {
		return err
	}

	// Provision Initial Attestation Key (IAK)
	if _, err := tpm.CreateIAK(srkAttrs.Parent); err != nil {
		return err
	}

	return nil
}

// Provisions a new Endorsement and Storage Root Key according to TCG
// Provisioning Guidance. The Endorsement Key (EK) is created and evicted
// to it's recommended persistent handle and a new Shared Storage Root Key
// (SRK) is created and evicted to it's recommended persistent handle.
func (tpm *TPM2) ProvisionOwner(
	soPIN keystore.Password) (*keystore.KeyAttributes, error) {

	tpm.logger.Info("Provisioning Owner Hierarchy")

	// Create EK
	ekAttrs, err := EKAttributesFromConfig(*tpm.config.EK, &tpm.policyDigest)
	if err != nil {
		return nil, err
	}
	ekAttrs.TPMAttributes.HierarchyAuth = soPIN
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return nil, err
	}

	// Create Shared SRK
	srkAttrs, err := SRKAttributesFromConfig(*tpm.config.SSRK, &tpm.policyDigest)
	if err != nil {
		return nil, err
	}
	srkAttrs.Parent = ekAttrs
	srkAttrs.TPMAttributes.HierarchyAuth = soPIN
	if err := tpm.CreateSRK(srkAttrs); err != nil {
		return nil, err
	}

	return srkAttrs, nil
}

// Writes an Endorsement Certificate to NV RAM. WARNING - this
// operation will overwrite an OEM certificate if it exists!
// If cert-handle is not provided, the certificate is saved to
// the x509 certificate store instead of writing to NV RAM.
// This provides to work around the 1024 byte limitation in the
// simulator and/or allows a user to conserve NV RAM in a real TPM.
func (tpm *TPM2) ProvisionEKCert(hierarchyAuth, ekCertDER []byte) error {

	tpm.logger.Info("Provisioning Endorsement Key Certificate - EK Credential Profile")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return err
	}

	ekCertHandle := tpm2.TPMHandle(ekCertIndex)

	if tpm.config.EK.CertHandle == 0 {
		ekCert, err := x509.ParseCertificate(ekCertDER)
		if err != nil {
			return err
		}
		err = tpm.certStore.ImportCertificate(ekCert)
		if err != nil {
			return err
		}
		return nil
	}

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: ekAttrs.TPMAttributes.Hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: ekCertHandle,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					NT:         tpm2.TPMNTOrdinary,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: true,
					NoDA:       true,
				},
				DataSize: uint16(len(ekCertDER)),
			}),
	}
	_, err = defs.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	write := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: ekAttrs.TPMAttributes.Hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: ekCertDER,
		},
		Offset: 0,
	}
	if _, err := write.Execute(tpm.transport); err != nil {
		tpm.logger.Error(err)
		return err
	}

	return nil
}

// Captures platform Golden Integrity Measurements as described
// in TCG TPM 2.0 Provisioning Guidance - Section 7.6 - Golden
// Measurements.
//
// Performs a sum across all PCR banks and their associated
// values using the hash function defined in the TPM section
// of the platform configuration file. Any errors encountered
// are treated as Fatal.
//
// TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
func (tpm *TPM2) GoldenMeasurements() []byte {
	tpm.logger.Info("Calculating Platform Golden Measurement")
	var gold, extend []byte
	digest := tpm.hash.New()
	digest.Reset()
	// Read all available banks and their PCR values
	banks, err := tpm.ReadPCRs(tpm2SupportedPCRs)
	if err != nil {
		tpm.logger.Fatal(err)
	}
	// Create golden PCR that stores the final sum of
	// all PCR values across all banks.
	for _, bank := range banks {
		for _, pcr := range bank.PCRs {
			extend = append(extend, pcr.Value...)
			digest.Write(extend)
			gold = digest.Sum(nil)
			extend = gold
			digest.Reset()
		}
	}
	// Recursively walk each directory configured for
	// file integrity monitoring and sum each file for
	// inclusion in the golden measurements.
	for _, dir := range tpm.config.FileIntegrity {
		dirSum := tpm.fileIntegritySum(dir)
		digest.Write(dirSum)
		gold = digest.Sum(nil)
	}
	return gold
}

// Returns the Golden Integrity Measurement and Policy Digest ready
// to be attached to a key.
func (tpm *TPM2) CreatePlatformPolicy() error {

	// Capture platform measurements and extend the Golden
	// Integrity Measurement into the platform selected PCR
	// specified in the platform configuration file
	measurement := tpm.GoldenMeasurements()

	tpm.logger.Debugf(
		"tpm: extending golden integrity measurement to PCR %d",
		tpm.config.PlatformPCR)

	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(tpm.config.PlatformPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  measurement,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	// Read the golden PCR value - this is the value that's
	// needed to satisfy future PolicySessions
	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(uint(tpm.config.PlatformPCR)),
			},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}
	goldenPCR := pcrReadRsp.PCRValues.Digests[0].Buffer

	// Create a trial session to calculate the SRK policy digest
	trialSession, closer, err := tpm2.PolicySession(
		tpm.transport, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		tpm.logger.Error(err)
		return err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error(err)
		}
	}()

	// Create PCR selection using "platform-pcr" defined in the platform
	// configuration file TPM section.
	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
			},
		},
	}

	// Create policy digest for the selected PCR
	_, err = tpm2.PolicyPCR{
		PolicySession: trialSession.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	// Calculate the policy digest using the trial session
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("Golden Integrity Measurements: 0x%s", hex.EncodeToString(measurement))
	tpm.logger.Debugf("Platform PCR: 0x%s", hex.EncodeToString(goldenPCR))

	tpm.policyDigest = pgd.PolicyDigest

	return nil
}

// Returns the platform PCR policy digest
func (tpm *TPM2) PlatformPolicyDigest() tpm2.TPM2BDigest {
	return tpm.policyDigest
}

// Recursively sums a directory path using the Hash function
// specified in the TPM section of the platform configuration
// file.
func (tpm *TPM2) fileIntegritySum(dir string) []byte {
	var sum, extend []byte
	digest := tpm.hash.New()
	digest.Reset()

	tpm.logger.Info("Processing file integrity checks")
	tpm.logger.Info(yaml.Marshal(viper.Get("tpm.file-integrity")))

	var extendDir func(string) []byte
	extendDir = func(dir string) []byte {

		files, err := os.ReadDir(dir)
		if err != nil {
			tpm.logger.Fatalf("%s: %s", err, dir)
		}

		tpm.logger.Debugf(
			"Calculating %s integrity checksums in %s",
			tpm.hash.String(), dir)

		for _, f := range files {
			var bytes []byte

			fileName := f.Name()
			path := fmt.Sprintf("%s/%s", dir, fileName)

			if f.IsDir() {
				extendDir(path)
				continue
			}

			bytes, err = os.ReadFile(path)
			if err != nil {
				tpm.logger.Fatal(err)
			}

			tpm.logger.Debug(path)

			// Rather than creating a digest of the read bytes and
			// then concatenating this digest with the digest from
			// the last iteration, save a few cycles here by appending
			// the new bytes directly into the "extend" hash from the
			// last iteration and sum them together.
			extend = append(extend, bytes...)
			digest.Write(extend)
			sum = digest.Sum(nil)
			extend = sum
			digest.Reset()
		}

		if len(files) == 0 {
			// Empty directory. Write a null byte and move on.
			extend = append(extend, []byte{0x00}...)
			digest.Write(extend)
			sum = digest.Sum(nil)
			extend = sum
			digest.Reset()
		}
		return sum
	}

	extendDir(dir)
	return sum
}
