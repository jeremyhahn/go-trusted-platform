![alt text](https://github.com/jeremyhahn/go-trusted-platform/blob/main/public_html/images/logo.png?raw=true)


The `Trusted Platform` uses a [Trusted Platform Module (TPM)](https://en.wikipedia.org/wiki/Trusted_Platform_Module), [Secure Boot](https://en.wikipedia.org/wiki/UEFI), and a provided [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) to establish a Platform Root of Trust for Storage & Reporting, perform Local and [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html), encryption, signing, x509 certificate management, data integrity, intrusion detection, licensing, device provisioning and more.


## Overview

This project provides a toolkit and framework for building [Trusted Computing](https://en.wikipedia.org/wiki/Trusted_Computing) architectures and web services in Golang.

This project supports the following use cases:

* Original Equipment Manufacturer
* Platform Administrator / User
* IoT Cloud
* DevOps Automation
* Enterprise Network Management
* Mobile Device Management
* Secure Key Store
* Trusted Web Services Framework
* WebAuthN / FIDO2
* Automated Certificate Management
* PKI-as-a-Service
* Single Sign-On


For detailed documentation on the components used in this project, please refer to the [docs](docs/OVERVIEW.md).

## Build

#### Dependencies

* [Linux](https://www.debian.org/)
* [Make](https://www.gnu.org/software/make/)
* [Golang](https://go.dev/)

Optional dependencies:

* [SoftHSM](https://www.opendnssec.org/softhsm/)
* [YubiKey](https://www.yubico.com/)
* [YubiHSM](https://www.yubico.com/products/hardware-security-module/)
* Other PKCS #11 HSM

    For FIPS compliance, a FIPS certified token is required.


#### Build

Use the included `Makefile` to build and perform initial setup.

    # Build the binary
    make

    # Run tests
    make test


#### Configuration

Copy the [config file](configs/platform/config.dev.yaml) to `./config.yaml` (where you will run the `trusted-platform` binary). Edit the configuration file according to your environment and requirements.

The Trusted Platform will try to read the TPM Endorsement Key Certificate from NVRAM, however, not all TPM's have their certificates flashed to NVRAM. Next it will attempt to download the EK certificate from the Manufacturer website (currently only Intel is supported). If neither of these methods is able to locate your TPM EK certificate, you can try using the [tpm2_getekcertificate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_getekcertificate.1.md) tool to dump your TPM Endorsement Key certificate to the project directory where you will run the `trusted-platform` binary. Follow the example and use the `ECcert.bin` file name, or edit the platform configuration file to match the custom name for your certificate in the TPM section.

The default config uses a TPM simulator which is reset every time the platform starts. Be sure to set the simulator to false in the platform configuration file to start using your real TPM device.


##### Web Services

The platform includes a built-in web server to host the REST API. The provided configuration files start the web server on HTTP port 8080 and TLS port 8443. The OpenAPI docs can be browsed at `https://localhost:8443/swagger`.


Procedure to start the embedded web services for the first time:

    # Copy a config file to the local directory
    cp configs/platform/config.prod.yaml config.yaml

    # Run web services
    ./tpadm webservice

    # Navigate to OpenAPI docs
    xdg-open https://localhost:8443/swagger/



###### Passwords

Currently, only PKCS #8 file based private keys are supported. PKCS #11 is on the way.

During platform setup, a few passwords are collected to encrypt and password protect the PKCS #8 private keys.

* Root Certificate Authority Private Key Password
* Intermediate Certificate Authority Private Key Password
* Web Server TLS Private Key Password

To automate the platform setup for testing, these passwords can be set in the configuration file, which will cause the setup to bypass the inital prompts and use the passwords defined in the config. This mechanism should only be used for testing, evaluation or development.


## LUKS

At this time, preliminary support for LUKS is included in the `Makefile`. In the future, full LUKS integration will be provided through the platform.

To setup an ecnrypted LUKS `trusted-data` volume for platform data, use the included `luks-create` Makefile target. 

    # Setup LUKS encrypted volume w/ Makefile
    make luks-create

If you don't trust the trusted `Makefile`, you can create your own key file and volume like this:

    # Generate LUKS key file
    echo -n "my-secret" > luks.key

    # Generate strong key file w/ random bytes
    dd bs=2048 count=4 if=/dev/random of=luks.key

    # Create LUKS volume
    sudo cryptsetup luksFormat --type luks2 trusted-data.luks2 luks.key

Then you can use the `luks-mount` target to mount your volume prior to starting the platform.

Don't forget to remove your LUKS key from the system. In the future, this step will be fully automated and the key will be sealed to the TPM.


## Platform Startup & Local Attestation

When the platform starts up, the Certificate Authorities are initialized, resulting in a Root and Intermediate CA with public / private keys, a signing certificate, and a dedicated encryption key using each of the configured key
algorithms specified in the platform configuration file. The Intermediate CA
will have the Root CA's certificate imported to its trusted root store. Each CA's Certificate Revocation List is created and initialized with a dummy certificate.

After the CA is initialized, local system platform measurements are taken according to the platform configuration file, signed by the CA, and stored in the CA's internal blob store, along with the digest, signature, and checksum of the measurements. On subsequent startups, new system measurements are taken, a new digest is created and verified against the initial platform measurements signature. If the signature does not match (the state is different / unexpected), the platform will return a fatal error and terminate. In the future, it will also re-seal the platform by unmounting the LUKS volume and run a set of custom event handlers that allow responding to the unexpected state of the system using plugins.


## Remote Attestation

A remote attestation implementation using the procedure outlined by [tpm2-community](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html) is working, however, be sure to read the notes in the attestation directory regarding this approach.

To test it out using the provided `Makefile` targets.

    # Attestor
    make attestor

    # Verifier
    make verifier

After attestation completes, you should see a new `attestation` folder appears that looks something like this (on the verifier side):

This example demonstrates a Certificate Authority with PKCS #8, PKCS #11, and TPM 2.0 key store enabled, and RSA-PSS, ECDSA and Ed25519 keys configured to enable simultaneous signing with any of the configured keys. In addition, PKCS #8 and TPM 2.0 keys support secondary password protection, using key level passwords in addition to the PIN used to secure the keys at the hardware level. The passwords are stored in the *platform key store* as HMAC secrets with an optional PCR policy that allows retrieval of the password as long as the platform is in it's approved state. The key store PINs have the `.pin` extension in their file names, while secondary passwords are stored using only their common names.

Note that the TPM 2.0 spec does not support Twisted Edward Curves (Ed25519). Many budget friendly HSM's don't support it either. Be sure to check the specifications on your PKCS #11 HSM to confirm support.

 ```
attestation/verifier/trusted-data/
├── b3177f70-89ed-6019-f568-07379867db76
│   ├── 050095df-a7c0-98c1-0b06-3ad5d80c8e8d.lock
│   ├── 050095df-a7c0-98c1-0b06-3ad5d80c8e8d.object
│   ├── 056b65e8-ebad-97d5-48ac-19862056d36f.lock
│   ├── 056b65e8-ebad-97d5-48ac-19862056d36f.object
│   ├── 089b7599-2598-f3c5-d90c-a1e5bddf6786.lock
│   ├── 089b7599-2598-f3c5-d90c-a1e5bddf6786.object
│   ├── 09044801-a3c7-fdbb-665a-ab3de814ff98.lock
│   ├── 09044801-a3c7-fdbb-665a-ab3de814ff98.object
│   ├── 0b1ba04d-8544-34a0-a784-724756dcf40f.lock
│   ├── 0b1ba04d-8544-34a0-a784-724756dcf40f.object
│   ├── 392ff10a-705f-97b0-8eab-614dabd5b9ec.lock
│   ├── 392ff10a-705f-97b0-8eab-614dabd5b9ec.object
│   ├── 3a5fd61e-b27f-b3a1-163f-cb8b2721edc2.lock
│   ├── 3a5fd61e-b27f-b3a1-163f-cb8b2721edc2.object
│   ├── 83fbc37e-2007-c8bc-f2b9-4ec9f45bf30b.lock
│   ├── 83fbc37e-2007-c8bc-f2b9-4ec9f45bf30b.object
│   ├── 8933c982-ccfb-ee2d-7e55-06c17ab52a07.lock
│   ├── 8933c982-ccfb-ee2d-7e55-06c17ab52a07.object
│   ├── 95bee1b0-0a2d-4d45-d3f5-b0e735692cd3.lock
│   ├── 95bee1b0-0a2d-4d45-d3f5-b0e735692cd3.object
│   ├── 9b039fd6-ddf4-4427-a1d0-2587cae6da0e.lock
│   ├── 9b039fd6-ddf4-4427-a1d0-2587cae6da0e.object
│   ├── c1b2cc95-4486-b3e8-0586-245d7e2cab99.lock
│   ├── c1b2cc95-4486-b3e8-0586-245d7e2cab99.object
│   ├── d92b8150-75b7-791a-a9f0-c775680c97d2.lock
│   ├── d92b8150-75b7-791a-a9f0-c775680c97d2.object
│   ├── ddc4bd89-ee49-365b-761e-a5a8018976a2.lock
│   ├── ddc4bd89-ee49-365b-761e-a5a8018976a2.object
│   ├── e8805a14-2fb4-861c-8d7c-0a59f0a9de8d.lock
│   ├── e8805a14-2fb4-861c-8d7c-0a59f0a9de8d.object
│   ├── f27f24ec-daf3-7d23-8cff-b6373321af52.lock
│   ├── f27f24ec-daf3-7d23-8cff-b6373321af52.object
│   ├── token.lock
│   └── token.object
├── blobs
│   ├── tpm
│   │   ├── device-id-001
│   │   │   ├── eventlog
│   │   │   ├── eventlog.digest
│   │   │   ├── eventlog.sha256
│   │   │   ├── eventlog.sig
│   │   │   ├── pcrs
│   │   │   ├── pcrs.digest
│   │   │   ├── pcrs.sha256
│   │   │   ├── pcrs.sig
│   │   │   ├── quote
│   │   │   ├── quote.digest
│   │   │   ├── quote.sha256
│   │   │   └── quote.sig
│   │   └── www.attestor.example.com
│   │       ├── ak.cer
│   │       ├── ak.cer.digest
│   │       ├── ak.cer.sha256
│   │       ├── ak.cer.sig
│   │       ├── eventlog
│   │       ├── eventlog.digest
│   │       ├── eventlog.sha256
│   │       ├── eventlog.sig
│   │       ├── pcrs
│   │       ├── pcrs.digest
│   │       ├── pcrs.sha256
│   │       ├── pcrs.sig
│   │       ├── quote
│   │       ├── quote.digest
│   │       ├── quote.sha256
│   │       └── quote.sig
│   └── .tpm2.rsa.cer
├── ca
│   ├── intermediate-ca.verifier.example.com
│   │   ├── encryption-keys
│   │   ├── hmac-keys
│   │   ├── intermediate-ca.verifier.example.com.pkcs8.ecdsa.key
│   │   ├── intermediate-ca.verifier.example.com.pkcs8.ecdsa.pub
│   │   ├── intermediate-ca.verifier.example.com.pkcs8.ed25519.key
│   │   ├── intermediate-ca.verifier.example.com.pkcs8.ed25519.pub
│   │   ├── intermediate-ca.verifier.example.com.pkcs8.rsa.key
│   │   ├── intermediate-ca.verifier.example.com.pkcs8.rsa.pub
│   │   ├── intermediate-ca.verifier.example.com.tpm2.ecdsa.key.bin
│   │   ├── intermediate-ca.verifier.example.com.tpm2.ecdsa.pub.bin
│   │   ├── intermediate-ca.verifier.example.com.tpm2.rsa.key.bin
│   │   ├── intermediate-ca.verifier.example.com.tpm2.rsa.pub.bin
│   │   ├── issued
│   │   │   └── www.verifier.example.com
│   │   │       ├── www.verifier.example.com.pkcs8.rsa.key
│   │   │       └── www.verifier.example.com.pkcs8.rsa.pub
│   │   ├── secrets
│   │   ├── signing-keys
│   │   └── x509
│   │       ├── ek.tpm2.rsa.cer
│   │       ├── intermediate-ca.attestor.example.com.pkcs8.rsa.cer
│   │       ├── intermediate-ca.verifier.example.com.pkcs11.ecdsa.cer
│   │       ├── intermediate-ca.verifier.example.com.pkcs11.ecdsa.crl
│   │       ├── intermediate-ca.verifier.example.com.pkcs11.rsa.cer
│   │       ├── intermediate-ca.verifier.example.com.pkcs11.rsa.crl
│   │       ├── intermediate-ca.verifier.example.com.pkcs8.ecdsa.cer
│   │       ├── intermediate-ca.verifier.example.com.pkcs8.ecdsa.crl
│   │       ├── intermediate-ca.verifier.example.com.pkcs8.ed25519.cer
│   │       ├── intermediate-ca.verifier.example.com.pkcs8.ed25519.crl
│   │       ├── intermediate-ca.verifier.example.com.pkcs8.rsa.cer
│   │       ├── intermediate-ca.verifier.example.com.pkcs8.rsa.crl
│   │       ├── intermediate-ca.verifier.example.com.tpm2.ecdsa.cer
│   │       ├── intermediate-ca.verifier.example.com.tpm2.ecdsa.crl
│   │       ├── intermediate-ca.verifier.example.com.tpm2.rsa.cer
│   │       ├── intermediate-ca.verifier.example.com.tpm2.rsa.crl
│   │       ├── root-ca.attestor.example.com.pkcs8.rsa.cer
│   │       ├── root-ca.verifier.example.com.pkcs11.ecdsa.cer
│   │       ├── root-ca.verifier.example.com.pkcs11.rsa.cer
│   │       ├── root-ca.verifier.example.com.pkcs8.ecdsa.cer
│   │       ├── root-ca.verifier.example.com.pkcs8.ed25519.cer
│   │       ├── root-ca.verifier.example.com.pkcs8.rsa.cer
│   │       ├── root-ca.verifier.example.com.tpm2.ecdsa.cer
│   │       ├── root-ca.verifier.example.com.tpm2.rsa.cer
│   │       ├── .tpm2.rsa.cer
│   │       ├── www.attestor.example.com.tpm2.rsa.cer
│   │       └── www.verifier.example.com.pkcs8.rsa.cer
│   └── root-ca.verifier.example.com
│       ├── encryption-keys
│       ├── hmac-keys
│       ├── issued
│       ├── root-ca.verifier.example.com.pkcs8.ecdsa.key
│       ├── root-ca.verifier.example.com.pkcs8.ecdsa.pub
│       ├── root-ca.verifier.example.com.pkcs8.ed25519.key
│       ├── root-ca.verifier.example.com.pkcs8.ed25519.pub
│       ├── root-ca.verifier.example.com.pkcs8.rsa.key
│       ├── root-ca.verifier.example.com.pkcs8.rsa.pub
│       ├── root-ca.verifier.example.com.tpm2.ecdsa.key.bin
│       ├── root-ca.verifier.example.com.tpm2.ecdsa.pub.bin
│       ├── root-ca.verifier.example.com.tpm2.rsa.key.bin
│       ├── root-ca.verifier.example.com.tpm2.rsa.pub.bin
│       ├── secrets
│       ├── signing-keys
│       └── x509
│           ├── root-ca.verifier.example.com.pkcs11.ecdsa.cer
│           ├── root-ca.verifier.example.com.pkcs11.ecdsa.crl
│           ├── root-ca.verifier.example.com.pkcs11.rsa.cer
│           ├── root-ca.verifier.example.com.pkcs11.rsa.crl
│           ├── root-ca.verifier.example.com.pkcs8.ecdsa.cer
│           ├── root-ca.verifier.example.com.pkcs8.ecdsa.crl
│           ├── root-ca.verifier.example.com.pkcs8.ed25519.cer
│           ├── root-ca.verifier.example.com.pkcs8.ed25519.crl
│           ├── root-ca.verifier.example.com.pkcs8.rsa.cer
│           ├── root-ca.verifier.example.com.pkcs8.rsa.crl
│           ├── root-ca.verifier.example.com.tpm2.ecdsa.cer
│           ├── root-ca.verifier.example.com.tpm2.ecdsa.crl
│           ├── root-ca.verifier.example.com.tpm2.rsa.cer
│           └── root-ca.verifier.example.com.tpm2.rsa.crl
├── etc
│   ├── config.yaml
│   └── softhsm.conf
├── log
│   └── trusted-platform.log
└── platform
    └── keystore
        ├── encryption-keys
        ├── hmac-keys
        │   ├── intermediate-ca.verifier.example.com
        │   │   ├── intermediate-ca.verifier.example.com.pkcs8.ecdsa.hmac.key.bin
        │   │   ├── intermediate-ca.verifier.example.com.pkcs8.ecdsa.hmac.pub.bin
        │   │   ├── intermediate-ca.verifier.example.com.pkcs8.ed25519.hmac.key.bin
        │   │   ├── intermediate-ca.verifier.example.com.pkcs8.ed25519.hmac.pub.bin
        │   │   ├── intermediate-ca.verifier.example.com.pkcs8.rsa.hmac.key.bin
        │   │   ├── intermediate-ca.verifier.example.com.pkcs8.rsa.hmac.pub.bin
        │   │   ├── intermediate-ca.verifier.example.com.tpm2.ecdsa.hmac.key.bin
        │   │   ├── intermediate-ca.verifier.example.com.tpm2.ecdsa.hmac.pub.bin
        │   │   ├── intermediate-ca.verifier.example.com.tpm2.rsa.hmac.key.bin
        │   │   └── intermediate-ca.verifier.example.com.tpm2.rsa.hmac.pub.bin
        │   ├── intermediate-ca.verifier.example.com.pin
        │   │   ├── intermediate-ca.verifier.example.com.pin.pkcs11.8.hmac.key.bin
        │   │   ├── intermediate-ca.verifier.example.com.pin.pkcs11.8.hmac.pub.bin
        │   │   ├── intermediate-ca.verifier.example.com.pin.tpm2.8.hmac.key.bin
        │   │   └── intermediate-ca.verifier.example.com.pin.tpm2.8.hmac.pub.bin
        │   ├── platform.pin
        │   │   ├── platform.pin.tpm2.8.hmac.key.bin
        │   │   └── platform.pin.tpm2.8.hmac.pub.bin
        │   ├── root-ca.verifier.example.com
        │   │   ├── root-ca.verifier.example.com.pkcs8.ecdsa.hmac.key.bin
        │   │   ├── root-ca.verifier.example.com.pkcs8.ecdsa.hmac.pub.bin
        │   │   ├── root-ca.verifier.example.com.pkcs8.ed25519.hmac.key.bin
        │   │   ├── root-ca.verifier.example.com.pkcs8.ed25519.hmac.pub.bin
        │   │   ├── root-ca.verifier.example.com.pkcs8.rsa.hmac.key.bin
        │   │   ├── root-ca.verifier.example.com.pkcs8.rsa.hmac.pub.bin
        │   │   ├── root-ca.verifier.example.com.tpm2.ecdsa.hmac.key.bin
        │   │   ├── root-ca.verifier.example.com.tpm2.ecdsa.hmac.pub.bin
        │   │   ├── root-ca.verifier.example.com.tpm2.rsa.hmac.key.bin
        │   │   └── root-ca.verifier.example.com.tpm2.rsa.hmac.pub.bin
        │   ├── root-ca.verifier.example.com.pin
        │   │   ├── root-ca.verifier.example.com.pin.pkcs11.8.hmac.key.bin
        │   │   ├── root-ca.verifier.example.com.pin.pkcs11.8.hmac.pub.bin
        │   │   ├── root-ca.verifier.example.com.pin.tpm2.8.hmac.key.bin
        │   │   └── root-ca.verifier.example.com.pin.tpm2.8.hmac.pub.bin
        │   └── www.verifier.example.com
        │       ├── www.verifier.example.com.pkcs8.rsa.hmac.key.bin
        │       └── www.verifier.example.com.pkcs8.rsa.hmac.pub.bin
        ├── issued
        ├── secrets
        └── signing-keys
```


## Status


This project is under active development, APIs can change at any moment.

The `main` branch will always build and run. Try it out!


- [ ] Trusted Platform
    - [ ] Supported Use Cases
        - [x] TPM Manufacturer
        - [x] Original Equipment (Device) Manufacturer
        - [x] Platform Administrator / End User
        - [x] Enterprise Network
        - [x] SOHO Network
    - [ ] Certificate Authority
        - [x] Key Storage Modules
            - [x] [PKCS 8](https://en.wikipedia.org/wiki/PKCS_8)
            - [x] [PKCS 11](https://en.wikipedia.org/wiki/PKCS_11)
            - [x] [TPM 2.0](https://en.wikipedia.org/wiki/Trusted_Platform_Module)
            - [x] [SoftHSM](https://www.opendnssec.org/softhsm/)
        - [x] Key Storage Backends
            - [x] File storage
            - [x] PKCS 11
            - [x] [TPM 2.0](https://en.wikipedia.org/wiki/Trusted_Platform_Module)
            - [x] [SoftHSM](https://www.opendnssec.org/softhsm/)
            - [ ] [Raft](https://raft.github.io/)
        - [x] Formats
            - [x] [PKCS 1](https://en.wikipedia.org/wiki/PKCS_1)
            - [x] [PKCS 8](https://en.wikipedia.org/wiki/PKCS_8)
            - [x] [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
        - [x] [TLS 1.3](https://words.filippo.io/tls-1-3-at-33c3/)
        - [x] Root CA
        - [x] Intermediate CA(s)
        - [x] RSA, ECDSA & EdDSA Key Algorithms
        - [x] Simultaneous issue/sign/verify using any supported algorithm
        - [x] Certificate & Key storage & retrieval
        - [x] Private trusted root certificate store
        - [x] Private trusted intermediate certificate store
        - [x] Distinct CA, TLS, encryption & signing keys
        - [x] RSA public & private encryption keys
        - [x] RSA, ECDSA & Ed21159 signing keys
        - [x] RSA PKCS1v15, RSA-PSS, ECDSA, & Ed25519 signature verification
        - [x] Create & Sign Certificate Signing Requests (CSR)
        - [x] x509 Certificate Revocation Lists (CRLs)
        - [x] Encoding & Decoding support for DER and PEM
        - [x] Automatic download & import Issuer CA(s) to trust store
        - [x] Automatic download & import Revocation Lists (CRLs)
        - [x] Parse & Create CA bundles
        - [x] Create Golang CertPool objects pre-initialized with CA certificates
        - [x] Create Golang tls.Config objects pre-initialized with Root & Client CA bundle and x509 Certificates (mTLS)
        - [x] Signed blob storage
        - [x] Install / Uninstall CA certificates to Operating System trust store
        - [ ] Online Certificate Status Protocol (OCSP)
        - [x] Sign TCG-CSR-IDEVID
        - [ ] Sign TCG-CSR-LDEVID
        - [x] Generate TCG compliant EK certificate
        - [x] Generate Attestation Key Certificate
        - [x] Forge Certificates (force specified public key)
        - [ ] Automatic Certificate Management Environment (ACME)
            - [ ] [acme-device-attest-03](https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03)
        - [ ] Cross-Signed Certificates with Let's Encrypt CA
    - [ ] TPM 2.0
        - [x] Provisioning per TCG recommended best practices
        - [x] Read Endorsement Key Certificate from NVRAM
        - [x] Download Endorsement Key Certificate from Manufacturer
            - [x] Intel
            - [ ] Optiga
        - [x] Read Endorsement Key Certificate from x509 certificate store
        - [x] Create EK Certificates
        - [x] Auto-import TPM Manufacturer CA chain
        - [x] Create RSA/ECC EK, SRK, AK, DevID keys and x509 certificates
        - [x] Verify Endorsement Key x509 Certificate w/ CA
        - [x] Credential challenge
        - [x] Activate credential
        - [x] Read Event Log
        - [x] Read Platform Configuration Registers (PCRs)
        - [x] Provide Attestation Key to Client
        - [x] Quote / Verify
        - [x] Create TCG-CSR-IDEVID certificate request
        - [ ] Create TCG-CSR-LDEVID certificate request
    - [ ] Command Line Interface
          [ ] [Linux man pages](docs/man)
            - [ ] CA
                - [x] info
                - [x] init
                - [x] install
                - [x] issue
                - [x] revoke
                - [x] show
                - [x] uninstall
            - [ ] Platform
                - [x] destroy
                - [x] install
                - [x] password
                - [x] provision
            - [ ] TPM
                - [x] clear
                - [x] ek
                - [x] eventlog
                - [x] info
                - [x] provision
        - [ ] Certificate Authority
            - [x] Issue Certificate
            - [x] Import Certificate to CA Trust Store
            - [x] Retrieve Public Key
            - [x] List Certificates
            - [x] Show Certificate
            - [x] Install to Operating System Trust Store
            - [x] Uninstall to Operating System Trust Store
            - [ ] Sign / verify (certificate & data)
            - [ ] Encrypt / Decrypt
            - [ ] Encode / Decode
            - [ ] Parse DER / PEM x509 certificates
        - [ ] Trusted Platform Module 2.0
            - [x] Create EK certificate
            - [x] Create Storage Root Key
            - [ ] Create Attestation Key
            - [ ] Validate EK Cert w/ CA
            - [ ] Auto-import EK Issuer Root & Intermediate CAs
            - [ ] Create Attestation Key
            - [ ] Credential challenge
            - [ ] Activate credential
            - [x] Event Log Parsing
            - [ ] Provide Attestation Key to Client
        - [x] Local Attestation
            - [x] Capture initial platform measurements
            - [x] Sign and store initial measurements
            - [ ] Capture new measurements on subsequent startups
            - [ ] Verify subsequent startup measurements
            - [ ] Terminate if verification fails
                - [ ] Exit with Fatal error
                - [ ] Re-seal the platform
                - [ ] Invoke custom event handlers
            - [ ] Client (Verifier)
                - [x] Auto-negotiated mTLSv1.3
                - [x] Get Endorsement Key (EK) and Certificate
                - [x] Get Attestation Key Profile (EK, AK, AK Name)
                - [x] Credential Challenge (TPM2_MakeCredential)
                - [x] Activate Credential (TPM2_ActivateCredential)
                - [x] Issue Attestation Key Certificate
                - [x] Verify Quote
        - [x] Remote Attestation
            - [x] Attestor (service consumer / server socket)
                - [x] gRPC service
                - [x] Insecure service
                    - [x] Exchange CA certificate bundle with Verifier
                    - [x] mTLS auto-negotiation
                    - [x] Require TLSv1.3
                - [x] Secure service (requires mTLS)
                    - [x] Get Endorsement Key (EK) and Certificate
                    - [x] Create Endorsement Key
                    - [x] Create Attestation Key
                    - [x] Activate Credential
                    - [x] Quote
                    - [ ] Accept service registration key
                    - [ ] DNS registration
                    - [ ] ACME device-attest enrollment
            - [ ] Verifier (service provider / client socket)
                - [x] Auto-negotiated mTLSv1.3
                - [x] Get Endorsement Key (EK) and Certificate
                - [x] Get Attestation Key Profile (EK, AK, AK Name)
                - [x] Credential Challenge (TPM2_MakeCredential)
                - [x] Activate Credential (TPM2_ActivateCredential)
                - [x] Issue Attestation Key x509 Certificate
                - [x] Verify Quote
                - [x] Provide AK Certificate w/ Secret
                - [ ] DNS registration
                - [ ] ACME device-attest enrollment
    - [ ] Web Services
        - [x] TLS 1.3
        - [x] Web server
        - [x] TLS Web Server
            - [x] Opaque private key
            - [ ] mTLS
        - [x] REST API
            - [x] Swagger / OpenAPI Docs
        - [ ] JSON Web Tokens
            - [x] Generate Token
            - [x] Refresh Token
            - [x] Validate Token
            - [x] Encrypted private key
            - [x] Opaque Private Key
    - [ ] gRPC Remote Attestation
        - [x] TLS 1.3
        - [x] Verifier (Service Provider)
            - [x] Opaque TLS Private Key
            - [x] mTLS auto-negotiation
            - [x] Get Endorsement Key Certificate
            - [x] Get Attestation Key Profile
            - [x] Make Credential Challenge
            - [x] Activate Credential
            - [x] Issue AK x509 Certificate
            - [x] Quote / Verify
            - [x] Automatic Device enrollment
        - [x] Attestor (Client)
            - [x] Opaque TLS Private Key
            - [x] mTLS auto-negotiation
            - [x] Get Endorsement Key Certificate
            - [x] Get Attestation Key Profile
            - [x] Activate Credential
            - [x] Quote / Verify
            - [x] Automatic Device enrollment
    - [ ] Plugin System
        - [ ] Install / uninstall
        - [ ] Sign / verify
    - [ ] Volume Encryption (LUKS)
        - [x] Preliminary Luks support for setup
        - [ ] Full LUKS integration to create and manage volumes
    - [ ] Automated Setup and Provisioning
        - [ ] Platform
            - [x] Create LUKS encrypted trusted-data volume
            - [x] Install and configure platform dependencies
        - [ ] Embedded Systems
            - [ ] Raspberry PI
                - [ ] Image builder
                    - [ ] Secure Boot
                    - [ ] OTP Password
                    - [ ] SD Card Writer
                    - [ ] Device Provisioning
                    - [ ] Device Onboarding
                - [x] Ansible system configuration
            - [ ] Arduino
                - [ ] ROM integrity check
                - [ ] Platform firmware
                - [ ] Firmware flasher
                - [ ] Device Provisioning
                - [ ] Device Onboarding
    - [ ] DNS Server
        - [ ] Automatic edge device registration
        - [ ] Dynamic DNS updates
    - [ ] High Availability
        - [ ] Gossip [(Partition Tolerance & Availability)](https://en.wikipedia.org/wiki/CAP_theorem)
            - [ ] Real-time platform network statistics
            - [ ] Health checking and monitoring
            - [ ] WAN Database Replication
            - [ ] Automated provisioning event system
        - [ ] Raft [(Consistency & Availability)](https://en.wikipedia.org/wiki/CAP_theorem)
            - [ ] LAN Database Replication
    - [ ] Intrusion Detection
        - [x] File Integrity Monitoring
        - [ ] Detect unauthorized software or hardware changes
        - [ ] Tamper Resistance
            - [ ] Pluggable event based response mechanisms
                - [ ] Platform shutdown
                - [ ] Unmount luks container (re-sealing the platform)
                - [ ] Delete luks volume & platform binary
                - [ ] Wipe file system

## Support

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn
