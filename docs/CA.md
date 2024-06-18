# Certificate Authority

The Certificate Authority (CA) provides a full-featured x509 certificate management system providing integrity checks, encryption / decryption and digital identies.

When the server starts for the first time, a Root and Intermediate Certificate Authority is created along with a web server certificate, and is ready to being servicing requests.

For increased security, the Root Certificate Authority (and especially it's private key) should be kept offline until a new Intermediate Certificate Authority needs to be created.

For maximum security, use a Trusted Platform Module (TPM), combined with Secure Boot, to provide critial BIOS, firmware, boot loader, and system integrity checks, and store all private keys offline, in a tamper resistant cryptographic co-processor, using opaque keys when needed. Use the CA to sign all executable binaries and verify their signatures prior to execution.


## Verifying Cerificates w/ OpenSSL

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
    cat localhost.crt intermediate-ca.crt > ca-bundle.crt

    # Create a single file containing the full certificate chain including the leaf
    cat localhost.crt intermediate-ca.crt root-ca.crt > localhost-bundle.crt
