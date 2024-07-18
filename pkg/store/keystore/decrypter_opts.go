package keystore

type DecrypterOpts struct {
	EncryptAttributes  KeyAttributes
	BlobCN             *string
	BlobData           []byte
	StoreEncryptedBlob bool
	Label              []byte
}

func NewDecrypterOpts() DecrypterOpts {
	return DecrypterOpts{}
}
