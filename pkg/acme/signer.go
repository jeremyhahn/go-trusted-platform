package acme

// type Signer struct {
// 	key    keystore.OpaqueKey
// 	random io.Reader
// 	jose.OpaqueSigner
// }

// func NewSigner(random io.Reader, key keystore.OpaqueKey) *Signer {
// 	return &Signer{
// 		key:    key,
// 		random: random,
// 	}
// }

// func (signer *Signer) Public() *jose.JSONWebKey {

// 	joseAlg, err := parseJOSEAlgorithm(signer.key.KeyAttributes().SignatureAlgorithm.String())
// 	if err != nil {
// 		panic(err)
// 	}

// 	switch signer.key.KeyAttributes().KeyAlgorithm {
// 	case x509.RSA:
// 		return &jose.JSONWebKey{
// 			Algorithm: string(joseAlg),
// 			Key:       signer.key.Public().(*rsa.PublicKey),
// 			KeyID:     signer.key.KeyAttributes().CN,
// 		}
// 	case x509.ECDSA:
// 		return &jose.JSONWebKey{
// 			Algorithm: string(joseAlg),
// 			Key:       signer.key.Public().(*ecdsa.PublicKey),
// 			KeyID:     signer.key.KeyAttributes().CN,
// 		}
// 	case x509.Ed25519:
// 		return &jose.JSONWebKey{
// 			Algorithm: string(joseAlg),
// 			Key:       signer.key.Public().(ed25519.PublicKey),
// 			KeyID:     signer.key.KeyAttributes().CN,
// 		}
// 	default:
// 		panic(fmt.Sprintf("unsupported key algorithm: %s",
// 			signer.key.KeyAttributes().KeyAlgorithm))
// 	}
// }

// // Algs returns a list of supported signing algorithms
// func (signer *Signer) Algs() []jose.SignatureAlgorithm {
// 	algs, err := parseJOSEAlgorithm(signer.key.KeyAttributes().SignatureAlgorithm.String())
// 	if err != nil {
// 		panic(err)
// 	}
// 	return []jose.SignatureAlgorithm{algs}
// }

// // SignPayload signs a payload with the current signing key using the given
// // algorithm.
// func (signer *Signer) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {

// 	keyAttrs := signer.key.KeyAttributes()
// 	hash := keyAttrs.Hash.New()
// 	hash.Reset()
// 	hash.Write(payload)
// 	digest := hash.Sum(nil)

// 	var opts crypto.SignerOpts
// 	if keystore.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
// 		opts = &rsa.PSSOptions{
// 			SaltLength: rsa.PSSSaltLengthEqualsHash,
// 			Hash:       keyAttrs.Hash,
// 		}
// 	} else {
// 		opts = keyAttrs.Hash
// 	}

// 	return signer.key.Sign(signer.random, digest, opts)
// }

// // Returns a Go x509 signature algorithm string to the equivalent jose.SignatureAlgorithm.
// func parseJOSEAlgorithm(x509Alg string) (jose.SignatureAlgorithm, error) {
// 	switch strings.ToUpper(x509Alg) {
// 	case "SHA256-RSA":
// 		return jose.RS256, nil
// 	case "SHA384-RSA":
// 		return jose.RS384, nil
// 	case "SHA512-RSA":
// 		return jose.RS512, nil
// 	case "SHA256-RSAPSS":
// 		return jose.RS256, nil
// 	case "SHA384-RSAPSS":
// 		return jose.RS384, nil
// 	case "SHA512-RSAPSS":
// 		return jose.RS512, nil
// 	case "ECDSA-SHA256":
// 		return jose.ES256, nil
// 	case "ECDSA-SHA384":
// 		return jose.ES384, nil
// 	case "ECDSA-SHA512":
// 		return jose.ES512, nil
// 	case "ED25519":
// 		return jose.EdDSA, nil
// 	default:
// 		return "", errors.New("unsupported x509 signature algorithm")
// 	}
// }
