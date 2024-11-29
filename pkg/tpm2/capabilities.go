package tpm2

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type PropertiesFixed struct {
	ActiveSessionsMax       uint32
	AuthSessionsActive      uint32
	AuthSessionsActiveAvail uint32
	AuthSessionsLoaded      uint32
	AuthSessionsLoadedAvail uint32
	Family                  string
	Fips1402                bool
	FwMajor                 int64
	FwMinor                 int64
	LoadedCurves            uint32
	LockoutCounter          uint32
	LockoutInterval         uint32
	LockoutRecovery         uint32
	Manufacturer            string
	Model                   string
	MaxAuthFail             uint32
	Memory                  uint32
	NVIndexesDefined        uint32
	NVIndexesMax            uint32
	NVWriteRecovery         uint32
	PersistentAvail         uint32
	PersistentLoaded        uint32
	PersistentMin           uint32
	Revision                string
	TransientAvail          uint32
	TransientMin            uint32
	VendorID                string
}

func (tpm *TPM2) IsFIPS140_2() (bool, error) {
	modesResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTModes),
		PropertyCount: 1,
	}.Execute(tpm.transport)
	if err != nil {
		return false, err
	}
	modes, err := modesResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return false, err
	}
	return modes.TPMProperty[0].Value == 1, nil
}

func (tpm *TPM2) FixedProperties() (*PropertiesFixed, error) {
	activeSessionsMax, err := activeSessionsMax(tpm.transport)
	if err != nil {
		return nil, err
	}
	persistentLoaded, err := persistentLoaded(tpm.transport)
	if err != nil {
		return nil, err
	}
	persistentAvail, err := persistentAvail(tpm.transport)
	if err != nil {
		return nil, err
	}
	persistentMin, err := persistentMin(tpm.transport)
	if err != nil {
		return nil, err
	}
	transientMin, err := transientMin(tpm.transport)
	if err != nil {
		return nil, err
	}
	transientAvail, err := transientAvail(tpm.transport)
	if err != nil {
		return nil, err
	}
	authSessionsLoaded, err := authSessionsLoaded(tpm.transport)
	if err != nil {
		return nil, err
	}
	authSessionsLoadedAvail, err := authSessionsLoadedAvail(tpm.transport)
	if err != nil {
		return nil, err
	}
	authSessionsActive, err := authSessionsActive(tpm.transport)
	if err != nil {
		return nil, err
	}
	authSessionsActiveAvail, err := authSessionsActiveAvail(tpm.transport)
	if err != nil {
		return nil, err
	}
	family, err := family(tpm.transport)
	if err != nil {
		return nil, err
	}
	fips1402, err := tpm.IsFIPS140_2()
	if err != nil {
		return nil, err
	}
	fwMajor, fwMinor, err := firmware(tpm.transport)
	if err != nil {
		return nil, err
	}
	lockoutCounter, err := lockoutCounter(tpm.transport)
	if err != nil {
		return nil, err
	}
	manufacturer, err := manufacturer(tpm.transport)
	if err != nil {
		return nil, err
	}
	maxAuthFail, err := maxAuthFail(tpm.transport)
	if err != nil {
		return nil, err
	}
	model, err := model(tpm.transport)
	if err != nil {
		return nil, err
	}
	nvIndexesDefined, err := nvIndexesDefined(tpm.transport)
	if err != nil {
		return nil, err
	}
	nvWriteRecovery, err := nvWriteRecovery(tpm.transport)
	if err != nil {
		return nil, err
	}
	nvIndexesMax, err := nvIndexesMax(tpm.transport)
	if err != nil {
		return nil, err
	}
	memory, err := memory(tpm.transport)
	if err != nil {
		return nil, err
	}
	revision, err := revision(tpm.transport)
	if err != nil {
		return nil, err
	}
	vendorID, err := vendorID(tpm.transport)
	if err != nil {
		return nil, err
	}
	return &PropertiesFixed{
		ActiveSessionsMax:       activeSessionsMax,
		AuthSessionsActive:      authSessionsActive,
		AuthSessionsActiveAvail: authSessionsActiveAvail,
		AuthSessionsLoaded:      authSessionsLoaded,
		AuthSessionsLoadedAvail: authSessionsLoadedAvail,
		Family:                  family,
		Fips1402:                fips1402,
		FwMajor:                 fwMajor,
		FwMinor:                 fwMinor,
		LockoutCounter:          lockoutCounter,
		Manufacturer:            manufacturer,
		MaxAuthFail:             maxAuthFail,
		Memory:                  memory,
		Model:                   model,
		NVIndexesDefined:        nvIndexesDefined,
		NVIndexesMax:            nvIndexesMax,
		NVWriteRecovery:         nvWriteRecovery,
		PersistentAvail:         persistentAvail,
		PersistentLoaded:        persistentLoaded,
		PersistentMin:           persistentMin,
		TransientAvail:          transientAvail,
		TransientMin:            transientMin,
		Revision:                revision,
		VendorID:                vendorID,
	}, nil
}

func memory(transport transport.TPM) (uint32, error) {
	memoryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMemory),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	memory, err := memoryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return memory.TPMProperty[0].Value, nil
}

func persistentLoaded(transport transport.TPM) (uint32, error) {
	persistentLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistent),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	persistentLoaded, err := persistentLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentLoaded.TPMProperty[0].Value, nil
}

func persistentAvail(transport transport.TPM) (uint32, error) {
	persistentAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistentAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	persistentAvail, err := persistentAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentAvail.TPMProperty[0].Value, nil
}

func persistentMin(transport transport.TPM) (uint32, error) {
	persistentMinResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistentMin),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	persistentMin, err := persistentMinResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentMin.TPMProperty[0].Value, nil
}

func transientMin(transport transport.TPM) (uint32, error) {
	transientLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRTransientMin),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	transientLoaded, err := transientLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return transientLoaded.TPMProperty[0].Value, nil
}

func transientAvail(transport transport.TPM) (uint32, error) {
	transientAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRTransientAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	transientAvail, err := transientAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return transientAvail.TPMProperty[0].Value, nil
}

func activeSessionsMax(transport transport.TPM) (uint32, error) {
	activeSessionsMaxResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTActiveSessionsMax),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	activeSessionsMax, err := activeSessionsMaxResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return activeSessionsMax.TPMProperty[0].Value, nil
}

func authSessionsActive(transport transport.TPM) (uint32, error) {
	authSessionsActiveResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRActive),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsActive, err := authSessionsActiveResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsActive.TPMProperty[0].Value, nil
}

func authSessionsActiveAvail(transport transport.TPM) (uint32, error) {
	authSessionsActiveAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRActiveAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsActiveAvail, err := authSessionsActiveAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsActiveAvail.TPMProperty[0].Value, nil
}

func authSessionsLoaded(transport transport.TPM) (uint32, error) {
	authSessionsLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRLoaded),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsLoaded, err := authSessionsLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsLoaded.TPMProperty[0].Value, nil
}

func authSessionsLoadedAvail(transport transport.TPM) (uint32, error) {
	authSessionsLoadedAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRLoadedAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsAvail, err := authSessionsLoadedAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsAvail.TPMProperty[0].Value, nil
}

func family(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFamilyIndicator),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", err
	}
	family, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, family.TPMProperty[0].Value)
	return string(buf), nil
}

func firmware(transport transport.TPM) (int64, int64, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtFwVersion1,
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, 0, err
	}
	firmware, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, 0, err
	}
	fw := firmware.TPMProperty[0].Value
	var fwMajor = int64((fw & 0xffff0000) >> 16)
	var fwMinor = int64(fw & 0x0000ffff)
	return fwMajor, fwMinor, nil
}

func loadedCurves(transport transport.TPM) (uint32, error) {
	loadedCurvesResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLoadedCurves),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	loadedCurves, err := loadedCurvesResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return loadedCurves.TPMProperty[0].Value, nil
}

func lockoutCounter(transport transport.TPM) (uint32, error) {
	lockoutCounterResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutCounter),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	lockoutCounter, err := lockoutCounterResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return lockoutCounter.TPMProperty[0].Value, nil
}

func lockoutRecovery(transport transport.TPM) (uint32, error) {
	lockoutRecoveryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutRecovery),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	lockoutRecovery, err := lockoutRecoveryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return lockoutRecovery.TPMProperty[0].Value, nil
}

func lockoutInterval(transport transport.TPM) (uint32, error) {
	lockoutIntervalResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutInterval),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	lockoutInterval, err := lockoutIntervalResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return lockoutInterval.TPMProperty[0].Value, nil
}

func manufacturer(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtManufacturer,
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", nil
	}
	manufacturer, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	var vendor TCGVendorID = TCGVendorID(manufacturer.TPMProperty[0].Value)
	return vendor.String(), nil
}

func model(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTVendorTPMType),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", nil
	}
	model, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, model.TPMProperty[0].Value)
	return string(buf), nil
}

func maxAuthFail(transport transport.TPM) (uint32, error) {
	maxAuthFailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMaxAuthFail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	maxAuthFail, err := maxAuthFailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return maxAuthFail.TPMProperty[0].Value, nil
}

func nvIndexesDefined(transport transport.TPM) (uint32, error) {
	nvIndexResponse, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRNVIndex),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	nvIndex, err := nvIndexResponse.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvIndex.TPMProperty[0].Value, nil
}

func nvIndexesMax(transport transport.TPM) (uint32, error) {
	nvIndexesMaxResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVIndexMax),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	nvIndexesMax, err := nvIndexesMaxResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvIndexesMax.TPMProperty[0].Value, nil
}

func nvWriteRecovery(transport transport.TPM) (uint32, error) {
	nvWriteRecoveryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVWriteRecovery),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	nvWriteRecovery, err := nvWriteRecoveryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvWriteRecovery.TPMProperty[0].Value, nil
}

func revision(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTRevision),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", err
	}
	revision, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	rev := fmt.Sprintf("%04d", revision.TPMProperty[0].Value)
	major := strings.TrimLeft(rev[:2], "0")
	minor := rev[2:]
	return fmt.Sprintf("%s.%s", major, minor), nil
}

func vendorID(transport transport.TPM) (string, error) {
	var vendorString string
	props := []tpm2.TPMPT{
		tpm2.TPMPTVendorString1,
		tpm2.TPMPTVendorString2,
		tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4}

	for _, prop := range props {
		vendorResp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}.Execute(transport)
		if err != nil {
			return "", err
		}
		vendorStr, err := vendorResp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return "", err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, vendorStr.TPMProperty[0].Value)
		vendorString += string(buf)
	}
	return vendorString, nil
}

// func (tpm *TPM2) DebugCapabilities() error {
// 	caps, err := tpm.FixedProperties()
// 	if err != nil {
// 		return err
// 	}

// 	tpm.logger.Debugf("Manufacturer: %s\n", caps.Manufacturer)
// 	tpm.logger.Debugf("Model: %s\n", caps.Model)
// 	tpm.logger.Debugf("Family: %s\n", caps.Family)
// 	tpm.logger.Debugf("Vendor ID: %s\n", caps.VendorID)
// 	tpm.logger.Debugf("Revision: %s\n", caps.Revision)
// 	tpm.logger.Debugf("Firmware: %d.%d\n", caps.FwMajor, caps.FwMinor)
// 	tpm.logger.Debugf("FIPS 140-2: %t\n", caps.Fips1402)

// 	tpm.logger.Debugf("Authorization Sessions Active: %d", caps.AuthSessionsActive)
// 	tpm.logger.Debugf("Authorization Sessions Active Available: %d", caps.AuthSessionsActiveAvail)

// 	tpm.logger.Debugf("Authorization Sessions Used: %d", caps.AuthSessionsLoaded)
// 	tpm.logger.Debugf("Authorization Sessions Loaded Available: %d", caps.AuthSessionsLoadedAvail)

// 	tpm.logger.Debugf("Max Auth Failures: %d", caps.MaxAuthFail)
// 	tpm.logger.Debugf("Memory: %d", caps.PersistentLoaded)

// 	tpm.logger.Debugf("Loaded Curves: %d", caps.LockoutCounter)

// 	tpm.logger.Debugf("Lockout Counter: %d", caps.LockoutCounter)
// 	tpm.logger.Debugf("Lockout Interval: %d", caps.LockoutInterval)
// 	tpm.logger.Debugf("Lockout Recovery: %d", caps.LockoutRecovery)

// 	tpm.logger.Debugf("NV Indexes Defined: %d", caps.NVIndexesDefined)
// 	tpm.logger.Debugf("NV Indexes Max: %d", caps.NVIndexesMax)
// 	tpm.logger.Debugf("NV Write Recovery: %d", caps.NVIndexesMax)

// 	tpm.logger.Debugf("Persistent Used: %d", caps.PersistentLoaded)
// 	tpm.logger.Debugf("Persistent Available: %d", caps.PersistentAvail)

// 	tpm.logger.Debugf("Transient Min: %d", caps.TransientMin)
// 	tpm.logger.Debugf("Transient Available: %d", caps.TransientAvail)

// 	return nil
// }

func (tpm *TPM2) Info() (string, error) {
	caps, err := tpm.FixedProperties()
	if err != nil {
		return "", err
	}

	var sb strings.Builder

	sb.WriteString("TPM Information\n")
	sb.WriteString(fmt.Sprintf("Manufacturer: %s\n", caps.Manufacturer))
	sb.WriteString(fmt.Sprintf("Vendor ID:    %s\n", caps.VendorID))
	sb.WriteString(fmt.Sprintf("Family:       %s\n", caps.Family))
	sb.WriteString(fmt.Sprintf("Revision:     %s\n", caps.Revision))
	sb.WriteString(fmt.Sprintf("Firmware:     %d.%d\n", caps.FwMajor, caps.FwMinor))
	sb.WriteString(fmt.Sprintf("Memory:       %d\n", caps.PersistentLoaded))
	sb.WriteString(fmt.Sprintf("Model:        %s\n", caps.Model))
	sb.WriteString(fmt.Sprintf("FIPS 140-2:   %t\n", caps.Fips1402))
	fmt.Println()

	sb.WriteString(fmt.Sprintf("Max Auth Failures: %d\n", caps.MaxAuthFail))
	sb.WriteString(fmt.Sprintf("Loaded Curves: %d\n", caps.LockoutCounter))
	fmt.Println()

	sb.WriteString(fmt.Sprintf("Authorization Sessions Active:           %d\n", caps.AuthSessionsActive))
	sb.WriteString(fmt.Sprintf("Authorization Sessions Active Available: %d\n", caps.AuthSessionsActiveAvail))

	sb.WriteString(fmt.Sprintf("Authorization Sessions Used:             %d\n", caps.AuthSessionsLoaded))
	sb.WriteString(fmt.Sprintf("Authorization Sessions Loaded Available: %d\n", caps.AuthSessionsLoadedAvail))

	sb.WriteString(fmt.Sprintf("Lockout Counter:  %d\n", caps.LockoutCounter))
	sb.WriteString(fmt.Sprintf("Lockout Interval: %d\n", caps.LockoutInterval))
	sb.WriteString(fmt.Sprintf("Lockout Recovery: %d\n", caps.LockoutRecovery))

	sb.WriteString(fmt.Sprintf("NV Indexes Defined: %d\n", caps.NVIndexesDefined))
	sb.WriteString(fmt.Sprintf("NV Indexes Max:     %d\n", caps.NVIndexesMax))
	sb.WriteString(fmt.Sprintf("NV Write Recovery:  %d\n", caps.NVIndexesMax))

	sb.WriteString(fmt.Sprintf("Persistent Used:      %d\n", caps.PersistentLoaded))
	sb.WriteString(fmt.Sprintf("Persistent Available: %d\n", caps.PersistentAvail))

	sb.WriteString(fmt.Sprintf("Transient Min:       %d\n", caps.TransientMin))
	sb.WriteString(fmt.Sprintf("Transient Available: %d\n", caps.TransientAvail))
	fmt.Println()

	return sb.String(), nil
}
