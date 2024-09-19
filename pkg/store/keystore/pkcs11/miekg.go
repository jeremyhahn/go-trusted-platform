package pkcs11

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/miekg/pkcs11"
	libpkcs11 "github.com/miekg/pkcs11"
)

var (
	ErrInvalidSlot = errors.New("pkcs11: invalid slot")
)

type PKCS11 struct {
	logger  *logging.Logger
	config  *Config
	ctx     *libpkcs11.Ctx
	session *libpkcs11.SessionHandle
}

// Opens a new PKCS #11 session and using the library and settings
// provided in the platform configuration file.
func NewPKCS11(
	logger *logging.Logger,
	config *Config) (*PKCS11, error) {

	var err error

	// Instantiate miekg's PKCS11 wrapper
	ctx := libpkcs11.New(config.Library)
	if err = ctx.Initialize(); err != nil {
		logger.MaybeError(err)
	}
	// defer ctx.Destroy()
	// defer ctx.Finalize()

	return &PKCS11{
		logger: logger,
		config: config,
		ctx:    ctx,
	}, err
}

// Returns the underlying PKCS #11 library
func (pkcs11 PKCS11) Lib() *libpkcs11.Ctx {
	return pkcs11.ctx
}

// Returns a session to the token. If a session is not currently open, a new
// session is opened and returned to the caller, otherwise a new session
// is opened and returned.
func (pkcs11 *PKCS11) Session() (libpkcs11.SessionHandle, error) {

	if pkcs11.session != nil {
		return *pkcs11.session, nil
	}

	var err error

	// Get slot list
	slots, err := pkcs11.ctx.GetSlotList(true)
	if err != nil {
		pkcs11.logger.Error(err)
		return 0, err
	}

	// Open a new session
	session, err := pkcs11.ctx.OpenSession(
		slots[*pkcs11.config.Slot], libpkcs11.CKF_SERIAL_SESSION|libpkcs11.CKF_RW_SESSION)
	if err != nil {
		pkcs11.logger.Error(err)
		return 0, err
	}
	pkcs11.session = &session

	return *pkcs11.session, nil
}

// Log into the token using the provided PIN. You must
// call Logout when done to prevent leaks.
func (p11 *PKCS11) Login() error {

	// Get slot list
	slots, err := p11.ctx.GetSlotList(true)
	if err != nil {
		return err
	}

	if p11.session == nil {
		// Open a new session on the configured slot
		session, err := p11.ctx.OpenSession(
			slots[*p11.config.Slot],
			pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return err
		}
		p11.session = &session
	}

	if err := p11.ctx.Login(
		*p11.session, libpkcs11.CKU_USER, p11.config.Pin); err != nil {
		p11.logger.Error(err)
		return err
	}

	// defer ctx.CloseSession(session)
	// defer ctx.Logout(session)
	return nil
}

// Closes the current session and logs the current user out of the token.
// The library remains available for future calls to Open.
func (pkcs11 *PKCS11) Close() error {
	if err := pkcs11.ctx.Logout(*pkcs11.session); err != nil {
		pkcs11.logger.Error(err)
		return err
	}
	if err := pkcs11.ctx.CloseSession(*pkcs11.session); err != nil {
		pkcs11.logger.Error(err)
		return err
	}
	return nil
}

// Destroys the session and signals the cryptoki library it's done being used.
// Thsi library is no longer available for calls to Open.
func (pkcs11 *PKCS11) Destroy() error {
	if pkcs11 != nil {
		if err := pkcs11.ctx.Finalize(); err != nil {
			pkcs11.logger.Error(err)
			return err
		}
		pkcs11.ctx.Destroy()
	}
	return nil
}

func (pkcs11 *PKCS11) DebugLibraryInfo() {
	info, err := pkcs11.ctx.GetInfo()
	if err != nil {
		pkcs11.logger.FatalError(err)
	}
	pkcs11.logger.Debug("PKCS #11 Library Info")
	pkcs11.logger.Debugf("  Manufacturer: %s", info.ManufacturerID)
	pkcs11.logger.Debugf("  Description: %s", info.LibraryDescription)
	pkcs11.logger.Debugf("  Version: %d.%d",
		info.LibraryVersion.Major, info.LibraryVersion.Minor)
	pkcs11.logger.Debugf("  Cryptoki: %d.%d",
		info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
	pkcs11.logger.Debugf("  Module: %s", pkcs11.config.Library)
	pkcs11.logger.Debugf("  Module Configuration: %s", pkcs11.config.LibraryConfig)
}

func (pkcs11 *PKCS11) DebugSlots() {

	slots, err := pkcs11.ctx.GetSlotList(true)
	if err != nil {
		pkcs11.logger.FatalError(err)
	}

	for _, slot := range slots {

		info, err := pkcs11.ctx.GetSlotInfo(slot)
		if err != nil {
			pkcs11.logger.FatalError(err)
		}

		pkcs11.logger.Debugf("PKCS #11 Hardware Info - Slot %d", slot)

		token, err := pkcs11.ctx.GetTokenInfo(slot)
		if err != nil {
			pkcs11.logger.FatalError(err)
		}

		pkcs11.logger.Debugf("  Label:\t\t    %s", token.Label)
		pkcs11.logger.Debugf("  Description: %s", info.SlotDescription)
		pkcs11.logger.Debugf("  Manufacturer: %s", info.ManufacturerID)
		pkcs11.logger.Debugf("  Model:\t\t    %s", token.Model)
		pkcs11.logger.Debugf("  Serial:\t\t    %s", token.SerialNumber)
		pkcs11.logger.Debugf("  Hardware:\t\t    %d.%d",
			token.HardwareVersion.Major, token.HardwareVersion.Minor)
		pkcs11.logger.Debugf("  Firmware:\t\t    %d.%d",
			token.FirmwareVersion.Major, token.FirmwareVersion.Minor)
		pkcs11.logger.Debugf("  PIN min/max:\t    %d/%d", token.MinPinLen, token.MaxPinLen)
		pkcs11.logger.Debugf("  Session Count:\t    %d", token.SessionCount)
		pkcs11.logger.Debugf("  RW Session Count:     %d", token.RwSessionCount)
		pkcs11.logger.Debugf("  Max Session Count:    %d", token.MaxSessionCount)
		pkcs11.logger.Debugf("  Free Private Memory:  %d", token.FreePrivateMemory)
		pkcs11.logger.Debugf("  Free Public Memory:   %d", token.FreePublicMemory)
		pkcs11.logger.Debugf("  Total Private Memory: %d", token.TotalPrivateMemory)
		pkcs11.logger.Debugf("  Total Public Memory:  %d", token.TotalPublicMemory)
		pkcs11.logger.Debugf("  UTC Time:\t\t\t%s", token.UTCTime)
	}
}

func (pkcs11 *PKCS11) PrintLibraryInfo() {
	info, err := pkcs11.ctx.GetInfo()
	if err != nil {
		pkcs11.logger.FatalError(err)
	}
	fmt.Printf("PKCS #11 Library Info\n")
	fmt.Printf("  Manufacturer:\t%s\n", info.ManufacturerID)
	fmt.Printf("  Description:\t%s\n", info.LibraryDescription)
	fmt.Printf("  Version:\t%d.%d\n",
		info.LibraryVersion.Major, info.LibraryVersion.Minor)
	fmt.Printf("  Cryptoki:\t%d.%d\n",
		info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
	fmt.Printf("  Module:\t%s\n", pkcs11.config.Library)
	fmt.Printf("  Config:\t%s\n", pkcs11.config.LibraryConfig)
	fmt.Println()
}

func (pkcs11 *PKCS11) PrintTokenInfo() {

	slots, err := pkcs11.ctx.GetSlotList(true)
	if err != nil {
		pkcs11.logger.FatalError(err)
	}

	for _, slot := range slots {

		info, err := pkcs11.ctx.GetSlotInfo(slot)
		if err != nil {
			pkcs11.logger.FatalError(err)
		}

		fmt.Printf("PKCS #11 Hardware Info - Slot %d\n", slot)

		token, err := pkcs11.ctx.GetTokenInfo(slot)
		if err != nil {
			pkcs11.logger.FatalError(err)
		}

		fmt.Printf("  Label:\t\t%s\n", token.Label)
		fmt.Printf("  Description:\t\t%s\n", info.SlotDescription)
		fmt.Printf("  Manufacturer:\t\t%s\n", token.ManufacturerID)
		fmt.Printf("  Model:\t\t%s\n", token.Model)
		fmt.Printf("  Serial:\t\t%s\n", token.SerialNumber)
		fmt.Printf("  Hardware:\t\t%d.%d\n",
			token.HardwareVersion.Major, token.HardwareVersion.Minor)
		fmt.Printf("  Firmware:\t\t%d.%d\n",
			token.FirmwareVersion.Major, token.FirmwareVersion.Minor)
		fmt.Printf("  PIN min/max:\t\t%d/%d\n", token.MinPinLen, token.MaxPinLen)
		fmt.Printf("  Session Count:\t%d\n", token.SessionCount)
		fmt.Printf("  RW Session Count:\t%d\n", token.RwSessionCount)
		fmt.Printf("  Max Session Count:\t%d\n", token.MaxSessionCount)
		fmt.Printf("  Free Private Memory:\t%d\n", token.FreePrivateMemory)
		fmt.Printf("  Free Public Memory:\t%d\n", token.FreePublicMemory)
		fmt.Printf("  Total Private Memory:\t%d\n", token.TotalPrivateMemory)
		fmt.Printf("  Total Public Memory:\t%d\n", token.TotalPublicMemory)
		fmt.Printf("  UTC Time:\t\t\t%s\n", token.UTCTime)
		fmt.Println()
	}
}
