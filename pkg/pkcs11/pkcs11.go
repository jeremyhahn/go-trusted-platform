package pkcs11

import (
	"fmt"

	"github.com/miekg/pkcs11"
	libpkcs11 "github.com/miekg/pkcs11"
)

type PKCS11 struct {
	session pkcs11.SessionHandle
}

func NewPKCS11(config Config) (*PKCS11, error) {

	lib := libpkcs11.New(config.Library)
	err := lib.Initialize()
	if err != nil {
		return nil, err
	}
	defer lib.Destroy()
	defer lib.Finalize()

	slots, err := lib.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := lib.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer lib.CloseSession(session)

	err = lib.Login(session, pkcs11.CKU_USER, "5678")
	if err != nil {
		panic(err)
	}
	defer lib.Logout(session)

	lib.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, err := lib.Digest(session, []byte("this is a string"))
	if err != nil {
		panic(err)
	}

	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()

	return &PKCS11{
		session: session,
	}, nil
}
