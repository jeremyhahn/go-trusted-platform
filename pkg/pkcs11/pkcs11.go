package pkcs11

import (
	"errors"

	"github.com/miekg/pkcs11"
	libpkcs11 "github.com/miekg/pkcs11"
	"github.com/op/go-logging"
)

var (
	ErrInvalidSlot = errors.New("pkcs11: invalid slot")
)

type PKCS11 struct {
	logger  *logging.Logger
	config  Config
	ctx     *libpkcs11.Ctx
	session libpkcs11.SessionHandle
	// ca.KeyStore
}

// Opens a new PKCS #11 session and using the library and settings
// provided in the platform configuration file.
func NewPKCS11(
	logger *logging.Logger,
	config Config) (PKCS11, error) {

	// Instantiate miekg's PKCS11 wrapper
	ctx := libpkcs11.New(config.Library)
	if err := ctx.Initialize(); err != nil {
		if err != nil {
			logger.Error(err)
			return PKCS11{}, err
		}
	}
	// defer ctx.Destroy()
	// defer ctx.Finalize()

	// Get slot list
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		logger.Error(err)
		return PKCS11{}, err
	}

	// Open a new session on the configured slot
	session, err := ctx.OpenSession(slots[config.Slot], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		logger.Error(err)
		return PKCS11{}, err
	}
	// defer ctx.CloseSession(session)

	p := PKCS11{
		logger:  logger,
		config:  config,
		ctx:     ctx,
		session: session,
	}

	// Log into the token
	if err := p.Login(); err != nil {
		return PKCS11{}, err
	}

	// Get token info
	info, err := ctx.GetInfo()
	if err != nil {
		return PKCS11{}, err
	}

	logger.Debugf("pkcs11: Manufacturer: %s", info.ManufacturerID)
	logger.Debugf("pkcs11: Description: %s", info.LibraryDescription)
	logger.Debugf("pkcs11: Version: %d.%d",
		info.LibraryVersion.Major, info.LibraryVersion.Minor)
	logger.Debugf("pkcs11: Cryptoki: %d.%d",
		info.CryptokiVersion.Major, info.CryptokiVersion.Minor)

	logger.Debug("pkcs11: Slots Available")
	for _, slot := range slots {
		logger.Debugf("pkcs11: slot %d", slot)
	}

	return p, nil
}

func (pkcs11 PKCS11) Lib() *libpkcs11.Ctx {
	return pkcs11.ctx
}

// Returns a session to the token. If a session is not currently open, a new
// session is opened and returned to the caller, otherwise a new session
// is opened and returned.
func (pkcs11 PKCS11) Session() (libpkcs11.SessionHandle, error) {
	if pkcs11.session > 0 {
		return pkcs11.session, nil
	}

	var err error

	// Get slot list
	slots, err := pkcs11.ctx.GetSlotList(true)
	if err != nil {
		pkcs11.logger.Error(err)
		return 0, err
	}

	// Open a new session
	pkcs11.session, err = pkcs11.ctx.OpenSession(
		slots[pkcs11.config.Slot], libpkcs11.CKF_SERIAL_SESSION|libpkcs11.CKF_RW_SESSION)
	if err != nil {
		pkcs11.logger.Error(err)
		return 0, err
	}

	return pkcs11.session, nil
}

// Log into the token using the provided PIN. You must
// call Logout when done to prevent leaks.
func (pkcs11 PKCS11) Login() error {
	if err := pkcs11.ctx.Login(
		pkcs11.session, libpkcs11.CKU_USER, pkcs11.config.Pin); err != nil {
		pkcs11.logger.Error(err)
		return err
	}
	// defer ctx.Logout(session)
	return nil
}

// Closes the current session and logs the current user out of the token.
// The library remains available for future calls to Open.
func (pkcs11 PKCS11) Close() error {
	if err := pkcs11.ctx.CloseSession(pkcs11.session); err != nil {
		pkcs11.logger.Error(err)
		return err
	}
	if err := pkcs11.ctx.Logout(pkcs11.session); err != nil {
		pkcs11.logger.Error(err)
		return err
	}
	return nil
}

// Destroys the session and signals the cryptoki library it's done being used.
// Thsi library is no longer available for calls to Open.
func (pkcs11 PKCS11) Destroy() error {
	pkcs11.ctx.Destroy()
	if err := pkcs11.ctx.Finalize(); err != nil {
		pkcs11.logger.Error(err)
		return err
	}
	return nil
}
