# Certificate Authority

The Certificate Authority (CA) provides a full-featured "TPM and Attestation Aware" x509 certificate management system providing TLS certificates, device certificates, signing, encryption, and compliance with TCG certificate attributes and data structures.

When the server starts for the first time, Root and Intermediate Certificate Authorities are created with RSA, ECDSA, and Ed25519 private keys and x509 certifiates per the platform configuration file. A TLS certificate is issued for the embedded web server using the algorithm specified in the configuration file.

For maximum security, store keys in a Trusted Platform Module (TPM) or PKCS #11 Hardware Security Module (HSM) that uses a tamper resistant cryptographic co-processor, and use opaque keys instead of raw key bytes. Use the CA to sign all executable binaries and verify their signatures prior to execution.


## Verifying Certificates w/ OpenSSL

The generated certificates can be verified with OpenSSL.

    # Verify x509 Certificate Chain - CA, Intermediate & Server
    openssl verify \
        -CAfile db/certs/intermediate-ca/trusted-root/root-ca.crt \
        -untrusted db/certs/intermediate-ca/intermediate-ca.crt \
        db/certs/intermediate-ca/issued/localhost/localhost.crt

    # Verify HTTPS
    openssl s_client \
        -connect localhost:8443 \
        -servername localhost  | openssl x509 -noout -text

    # Verify x509 PEM certificate
    openssl x509 -in localhost.crt -text -noout

    # Verify RSA Private Key
    openssl rsa -in root-ca.key -text (-check)

    # Verify RSA Public Key
    openssl rsa -pubin -in root-ca.pub -text

    # Create "ca-bundle" file
    cat intermediate-ca.crt root-ca.crt > ca-bundle.crt

    # Create a single file containing the full certificate chain including the leaf
    cat localhost.crt intermediate-ca.crt root-ca.crt > localhost-bundle.crt

    # Decrypt RSA Private Key
    openssl pkcs8 -topk8 -inform pem -in root-ca.rsa.pkcs8 -outform pem -nocrypt -out root-ca.rsa.pkcs8.pem


[The Most Common OpenSSL Commands](https://www.sslshopper.com/article-most-common-openssl-commands.html)


# Key Usages

[Key usage extensions and extended key usage](https://help.hcltechsw.com/domino/10.0.1/admin/conf_keyusageextensionsandextendedkeyusage_r.html)