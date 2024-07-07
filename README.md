![alt text](https://github.com/jeremyhahn/go-trusted-platform/blob/main/public_html/images/logo.png?raw=true)


The `Trusted Platform` uses a [Trusted Platform Module (TPM)](https://en.wikipedia.org/wiki/Trusted_Platform_Module), [Secure Boot](https://en.wikipedia.org/wiki/UEFI), and a provided [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) to establish a Platform Root of Trust, perform Local and [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html), encryption, signing, x509 certificate management, data integrity, intrusion detection, licensing and more.


## Overview

For detailed documentationon the components used in this project, please refer to the [docs](docs/OVERVIEW.md).

## Build

#### Dependencies

* [Linux](https://www.debian.org/)
* [Make](https://www.gnu.org/software/make/)
* [Golang](https://go.dev/)

Optional dependencies:

* [SoftHSM](https://www.opendnssec.org/softhsm/)
* [YubiKey](https://www.yubico.com/)
* [YubiHSM](https://www.yubico.com/products/hardware-security-module/)

For FIPS compliance, you must use a FIPS Series or otherwise certified token.


#### Build

Use the included `Makefile` to build and perform initial setup.

    # Build the binary
    make

    # Run tests
    make test


#### Configuration

Copy the [config file](configs/platform/config.dev.yaml) to the root of the project directory where you will run the `trusted-platform` binary. Edit the configuration file according to your environment and requirements.

Use [tpm2_getekcertificate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_getekcertificate.1.md) to dump your TPM Endorsement Key to the project directory where you will run the `trusted-platform` binary. Follow the example and use the ECcert.bin file name, or edit the config file to match the custom name you choose for your EK certificate in the TPM section of the config.

Start the embedded web services:

    # Run web services
    ./trusted-platform webservice --debug

The default config uses a TPM simulator which is reset every time the platform starts. Be sure to disable it to use your real TPM device.


###### Passwords

Currently, only PKCS #8 file based private keys are supported. PKCS #11 is on the way.

During platform setup, several passwords are collected to encrypt and password protect the PKCS #8 private keys.

* Root Certificate Authority Private Key Password
* Intermediate Certificate Authority Private Key Password
* Web Server Private Key Password

To automate the platform setup for testing, these passwords can be set in the configuration file, which will cause the setup to bypass the inital prompts and use the passwords defined in the config. This mechanism should only be used for testing, evaluation or development.


## LUKS

At this time, preliminary support for LUKS is included in the `Makefile`. In the future, full LUKS integration will be provided.

To setup an ecnrypted LUKS `trusted-data` volume for platform data, use the included `luks-create` Makefile target. 

    # Setup LUKS encrypted volume w/ Makefile
    make luks-create

If you don't trust the trusted `Makefile`, you can create your own key file and volume something like this:

    # Generate LUKS key file
    echo -n "my-secret" > luks.jey

    # Generate strong key file w/ random bytes
    dd bs=2048 count=4 if=/dev/random of=luks.key

    # Create LUKS volume
    sudo cryptsetup luksFormat --type luks2 trusted-data.luks2 luks.key

Then you can use the `luks-mount` target to mount your volume prior to starting the platform.

Don't forget to remove your LUKS key from the system. In the future, this step will be fully automated and the key will be sealed to the TPM Endorsement Key.


## Platform Startup & Local Attestation

When the platform starts up, the Certificate Authorities are initialized, resulting in a Root and Intermeidate CA with public / private keys, a signing certificate, and a dedicated encryption key. The Intermediate CA will have the Root CA's certificate imported to its trusted root store. Each CA's Certificate Revocation List is created and initialized with a dummy certificate.

After the CA is initialized, local system platform measurements are taken according to the platform configuration file, signed by the CA, and stored in the CA's internal blob storage along with it's signature. Each time the platform is subsequently started, new system measurements are taken, a new digest is created from the new measurements, and verified against the initial platform measurements signature. If the signgature does not match (verification failed), the platform will return a fatal error and terminate. 

In the future, custom local attestation failure event handlers will be supported.


## Remote Attestation

Full remote attestation is working. Test it out using the provided `Makefile` targets.

    # Attestor
    make attestor

    # Verifier
    make verifier

After attestation completes, you should see a new `attestation` folder appear with something like this:

 ```
.
attestation/
├── attestor
│   └── trusted-data
│       ├── ca
│       │   ├── intermediate-ca.example.com
│       │   │   ├── blobs
│       │   │   │   └── tpm
│       │   │   │       ├── attestor.example.com
│       │   │   │       │   ├── ak-cert.cer
│       │   │   │       │   ├── ak-cert.cer.digest
│       │   │   │       │   ├── ak-cert.cer.sha256
│       │   │   │       │   ├── ak-cert.cer.sig
│       │   │   │       │   ├── ak-cert.crt
│       │   │   │       │   ├── eventlog
│       │   │   │       │   ├── eventlog.digest
│       │   │   │       │   ├── eventlog.sha256
│       │   │   │       │   ├── eventlog.sig
│       │   │   │       │   ├── pcrs
│       │   │   │       │   ├── pcrs.digest
│       │   │   │       │   ├── pcrs.sha256
│       │   │   │       │   ├── pcrs.sig
│       │   │   │       │   ├── quote
│       │   │   │       │   ├── quote.digest
│       │   │   │       │   ├── quote.sha256
│       │   │   │       │   └── quote.sig
│       │   │   │       └── intermediate-ca.example.com
│       │   │   │           ├── ek-cert.crt
│       │   │   │           ├── ek-cert.crt.digest
│       │   │   │           ├── ek-cert.crt.sha256
│       │   │   │           └── ek-cert.crt.sig
│       │   │   ├── crl
│       │   │   ├── encryption-keys
│       │   │   │   └── intermediate-ca.example.com
│       │   │   │       ├── intermediate-ca.example.com.key
│       │   │   │       ├── intermediate-ca.example.com.key.pkcs8
│       │   │   │       ├── intermediate-ca.example.com.pub
│       │   │   │       ├── intermediate-ca.example.com.pub.pkcs1
│       │   │   │       └── intermediate-ca.example.com.sig
│       │   │   ├── intermediate-ca.example.com.bundle.crt
│       │   │   ├── intermediate-ca.example.com.cer
│       │   │   ├── intermediate-ca.example.com.crl
│       │   │   ├── intermediate-ca.example.com.crt
│       │   │   ├── intermediate-ca.example.com.key
│       │   │   ├── intermediate-ca.example.com.key.pkcs8
│       │   │   ├── intermediate-ca.example.com.pub
│       │   │   ├── intermediate-ca.example.com.pub.pkcs1
│       │   │   ├── issued
│       │   │   │   └── attestor.example.com
│       │   │   │       ├── attestor.example.com.cer
│       │   │   │       ├── attestor.example.com.crt
│       │   │   │       ├── attestor.example.com.key
│       │   │   │       ├── attestor.example.com.key.pkcs8
│       │   │   │       ├── attestor.example.com.pub
│       │   │   │       └── attestor.example.com.pub.pkcs1
│       │   │   ├── public-keys
│       │   │   │   ├── attestor.example.com.pub
│       │   │   │   └── root-ca.example.com.pub
│       │   │   ├── revoked
│       │   │   │   └── dummy
│       │   │   │       ├── dummy.cer
│       │   │   │       ├── dummy.crt
│       │   │   │       ├── dummy.key
│       │   │   │       ├── dummy.key.pkcs8
│       │   │   │       ├── dummy.pub
│       │   │   │       └── dummy.pub.pkcs1
│       │   │   ├── signing-keys
│       │   │   ├── trusted-intermediate
│       │   │   │   ├── CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.cer
│       │   │   │   └── CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.crt
│       │   │   └── trusted-root
│       │   │       ├── root-ca.example.com.cer
│       │   │       ├── root-ca.example.com.crt
│       │   │       ├── www.intel.com.cer
│       │   │       └── www.intel.com.crt
│       │   └── root-ca.example.com
│       │       ├── blobs
│       │       ├── crl
│       │       ├── encryption-keys
│       │       │   └── root-ca.example.com
│       │       │       ├── root-ca.example.com.key
│       │       │       ├── root-ca.example.com.key.pkcs8
│       │       │       ├── root-ca.example.com.pub
│       │       │       ├── root-ca.example.com.pub.pkcs1
│       │       │       └── root-ca.example.com.sig
│       │       ├── issued
│       │       ├── public-keys
│       │       ├── revoked
│       │       │   └── dummy
│       │       │       ├── dummy.cer
│       │       │       ├── dummy.crt
│       │       │       ├── dummy.key
│       │       │       ├── dummy.key.pkcs8
│       │       │       ├── dummy.pub
│       │       │       └── dummy.pub.pkcs1
│       │       ├── root-ca.example.com.cer
│       │       ├── root-ca.example.com.crl
│       │       ├── root-ca.example.com.crt
│       │       ├── root-ca.example.com.key
│       │       ├── root-ca.example.com.key.pkcs8
│       │       ├── root-ca.example.com.pub
│       │       ├── root-ca.example.com.pub.pkcs1
│       │       ├── signing-keys
│       │       ├── trusted-intermediate
│       │       └── trusted-root
│       ├── etc
│       │   └── config.yaml
│       └── log
│           └── trusted-platform.log
└── verifier
    └── trusted-data
        ├── ca
        │   ├── intermediate-ca.example.com
        │   │   ├── blobs
        │   │   │   └── tpm
        │   │   │       ├── attestor.example.com
        │   │   │       │   ├── ak.cer
        │   │   │       │   ├── ak.cer.digest
        │   │   │       │   ├── ak.cer.sha256
        │   │   │       │   ├── ak.cer.sig
        │   │   │       │   ├── eventlog
        │   │   │       │   ├── eventlog.digest
        │   │   │       │   ├── eventlog.sha256
        │   │   │       │   ├── eventlog.sig
        │   │   │       │   ├── pcrs
        │   │   │       │   ├── pcrs.digest
        │   │   │       │   ├── pcrs.sha256
        │   │   │       │   ├── pcrs.sig
        │   │   │       │   ├── quote
        │   │   │       │   ├── quote.digest
        │   │   │       │   ├── quote.sha256
        │   │   │       │   └── quote.sig
        │   │   │       ├── intermediate-ca.example.com
        │   │   │       │   ├── ek-cert.crt
        │   │   │       │   ├── ek-cert.crt.digest
        │   │   │       │   ├── ek-cert.crt.sha256
        │   │   │       │   └── ek-cert.crt.sig
        │   │   │       └── verifier.example.com
        │   │   │           ├── eventlog
        │   │   │           ├── eventlog.digest
        │   │   │           ├── eventlog.sha256
        │   │   │           ├── eventlog.sig
        │   │   │           ├── pcrs
        │   │   │           ├── pcrs.digest
        │   │   │           ├── pcrs.sha256
        │   │   │           ├── pcrs.sig
        │   │   │           ├── quote
        │   │   │           ├── quote.digest
        │   │   │           ├── quote.sha256
        │   │   │           └── quote.sig
        │   │   ├── crl
        │   │   ├── encryption-keys
        │   │   │   └── intermediate-ca.example.com
        │   │   │       ├── intermediate-ca.example.com.key
        │   │   │       ├── intermediate-ca.example.com.key.pkcs8
        │   │   │       ├── intermediate-ca.example.com.pub
        │   │   │       ├── intermediate-ca.example.com.pub.pkcs1
        │   │   │       └── intermediate-ca.example.com.sig
        │   │   ├── intermediate-ca.example.com.bundle.crt
        │   │   ├── intermediate-ca.example.com.cer
        │   │   ├── intermediate-ca.example.com.crl
        │   │   ├── intermediate-ca.example.com.crt
        │   │   ├── intermediate-ca.example.com.key
        │   │   ├── intermediate-ca.example.com.key.pkcs8
        │   │   ├── intermediate-ca.example.com.pub
        │   │   ├── intermediate-ca.example.com.pub.pkcs1
        │   │   ├── issued
        │   │   │   ├── attestor.example.com
        │   │   │   │   ├── attestor.example.com.cer
        │   │   │   │   ├── attestor.example.com.crt
        │   │   │   │   ├── attestor.example.com.key
        │   │   │   │   ├── attestor.example.com.key.pkcs8
        │   │   │   │   ├── attestor.example.com.pub
        │   │   │   │   └── attestor.example.com.pub.pkcs1
        │   │   │   └── verifier.example.com
        │   │   │       ├── verifier.example.com.cer
        │   │   │       ├── verifier.example.com.crt
        │   │   │       ├── verifier.example.com.key
        │   │   │       ├── verifier.example.com.key.pkcs8
        │   │   │       ├── verifier.example.com.pub
        │   │   │       └── verifier.example.com.pub.pkcs1
        │   │   ├── public-keys
        │   │   │   ├── attestor.example.com.pub
        │   │   │   ├── root-ca.example.com.pub
        │   │   │   └── verifier.example.com.pub
        │   │   ├── revoked
        │   │   │   └── dummy
        │   │   │       ├── dummy.cer
        │   │   │       ├── dummy.crt
        │   │   │       ├── dummy.key
        │   │   │       ├── dummy.key.pkcs8
        │   │   │       ├── dummy.pub
        │   │   │       └── dummy.pub.pkcs1
        │   │   ├── signing-keys
        │   │   ├── trusted-intermediate
        │   │   │   ├── CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.cer
        │   │   │   └── CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.crt
        │   │   └── trusted-root
        │   │       ├── root-ca.example.com.cer
        │   │       ├── root-ca.example.com.crt
        │   │       ├── www.intel.com.cer
        │   │       └── www.intel.com.crt
        │   └── root-ca.example.com
        │       ├── blobs
        │       ├── crl
        │       ├── encryption-keys
        │       │   └── root-ca.example.com
        │       │       ├── root-ca.example.com.key
        │       │       ├── root-ca.example.com.key.pkcs8
        │       │       ├── root-ca.example.com.pub
        │       │       ├── root-ca.example.com.pub.pkcs1
        │       │       └── root-ca.example.com.sig
        │       ├── issued
        │       ├── public-keys
        │       ├── revoked
        │       │   └── dummy
        │       │       ├── dummy.cer
        │       │       ├── dummy.crt
        │       │       ├── dummy.key
        │       │       ├── dummy.key.pkcs8
        │       │       ├── dummy.pub
        │       │       └── dummy.pub.pkcs1
        │       ├── root-ca.example.com.cer
        │       ├── root-ca.example.com.crl
        │       ├── root-ca.example.com.crt
        │       ├── root-ca.example.com.key
        │       ├── root-ca.example.com.key.pkcs8
        │       ├── root-ca.example.com.pub
        │       ├── root-ca.example.com.pub.pkcs1
        │       ├── signing-keys
        │       ├── trusted-intermediate
        │       └── trusted-root
        ├── etc
        │   └── config.yaml
        └── log
            └── trusted-platform.log
```


## Status


This project is under active development APIs can change at any moment.

The `main` branch will always build and run. Try it out!


- [ ] Trusted Platform
    - [ ] Certificate Authority
        - [ ] Key Storage
            - [x] [PKCS 1](https://en.wikipedia.org/wiki/PKCS_1)
            - [x] [PKCS 8](https://en.wikipedia.org/wiki/PKCS_8)
            - [ ] [PKCS 11](https://en.wikipedia.org/wiki/PKCS_11)
        - [x] Key Storage Backends
            - [x] File storage
            - [ ] PKCS 11
                - [ ] [TPM 2.0](https://en.wikipedia.org/wiki/Trusted_Platform_Module)
                - [ ] [SoftHSM](https://www.opendnssec.org/softhsm/)
                - [ ] [YubiKey](https://www.yubico.com/)
        - [x] Root CA
        - [x] Intermediate CA(s)
        - [x] x509 Certificates (RSA & ECC)
        - [x] Certificate & Key storage & retrieval
        - [x] Private trusted root certificate store
        - [x] Private trusted intermediate certificate store
        - [x] Distinct TLS, encryption & signing keys
        - [x] RSA public & private encryption keys
        - [x] RSA & ECC signing keys
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
    - [ ] TPM 2.0
        - [x] Read Endorsement Key Certificate from NVRAM
        - [x] Download Endorsement Key Certificate from Manufacturer
            - [x] Intel
            - [ ] Optiga
        - [x] Read Endorsement Key Certificate from file (tpm2_getekcertificate)
        - [x] Auto-import Platform Certificates (Manufacturer CA chain)
        - [x] Import ASN.1 DER encoded Endorsement Key Certificates
        - [x] Import PEM encoded Endorsement Key Certificates
        - [x] Create RSA Endorsement Key
        - [x] Create ECC Endorsement Key
        - [x] Create RSA Storage Root Key
        - [x] Create ECC Storage Root Key
        - [x] Create RSA Storage Root Key
        - [x] Create ECC Attestation Key
        - [x] Validate Endorsement Key x509 Certificate w/ CA
        - [x] Create Attestation Key from EK / SRK
        - [x] Credential challenge
        - [x] Activate credential
        - [x] Read / Parse Event Log
        - [x] Read Platform Configuration Registers (PCRs)
        - [x] Provide Attestation Key to Client
        - [x] Quote / Verify
    - [ ] Command Line Interface
        [ [ ] Linux man pages
            - [ ] CA
                - [x] install-ca-certificates
            - [ ] TPM
                - [x] import-ek
        - [ ] Certificate Authority
            - [x] Issue Certificate
            - [ ] Import Certificate to CA Trust Store
            - [x] Retrieve Public Key
            - [x] List Certificates
            - [x] Show Certificate
            - [x] Install to Operating System Trust Store
            - [x] Uninstall to Operating System Trust Store
            - [ ] Sign / verify (certificate & data)
            - [ ] RSA Encrypt / Decrypt
            - [ ] ECC Encrypt / Decrypt
            - [ ] Encode / Decode
            - [x] Parse DER / PEM x509 certificates
        - [ ] Trusted Platform Module 2.0
            - [x] Create RSA Endorsement Key
            - [ ] Create ECC Endorsement Key
            - [x] Create RSA Storage Root Key
            - [ ] Create ECC Storage Root Key
            - [x] Create RSA Storage Root Key
            - [ ] Create ECC Attestation Key
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
            - [x] Capture new measurements on subsequent startups
            - [x] Verify subsequent startup measurements
            - [x] Terminate if verification fails
                - [x] Exit with Fatal error
                - [ ] Re-seal the platform
                - [ ] Invoke custom event handlers
            - [ ] Client (Verifier)
                - [x] Auto-negotiated mTLSv1.3
                - [x] Get Endorsement Key (EK) and Certificate
                - [x] Get Attestation Key Profile (EK, AK, AK Name)
                - [x] Credential Challenge (TPM2_MakeCredential)
                - [x] Activate Credential ((TPM2_ActivateCredential)
                - [x] Issue Attestation Key Certificate
                - [x] Verify Quote
        - [x] Full Remote Attestation
            - [x] Server (Attestor)
                - [x] gRPC service
                - [x] Insecure service
                    - [x] Exchange CA certificate bundle with Verifier
                    - [x] Supports mTLS auto-negotiation
                    - [x] Require TLSv1.3
                - [x] Secure service (requires mTLS)
                    - [x] Get Endorsement Key (EK) and Certificate
                    - [x] Create Endorsement Key
                    - [x] Create Attestation Key
                    - [x] Activate Credential
                    - [x] Quote
                    - [ ] Accept service registration key
            - [ ] Client (Verifier)
                - [x] Auto-negotiated mTLSv1.3
                - [x] Get Endorsement Key (EK) and Certificate
                - [x] Get Attestation Key Profile (EK, AK, AK Name)
                - [x] Credential Challenge (TPM2_MakeCredential)
                - [x] Activate Credential ((TPM2_ActivateCredential)
                - [x] Issue Attestation Key x509 Certificate
                - [x] Verify Quote
                - [ ] Disseminate service registration
    - [ ] Web Services
        - [x] Web server
        - [x] TLS Web Server
            - [x] Encrypted private key
            - [ ] Opaque private key
            - [ ] mTLS
        - [x] REST API
            - [x] Swagger / OpenAPI Docs
        - [ ] JWT Authentication
            - [x] Generate Token
            - [x] Refresh Token
            - [x] Validate Token
            - [x] Encrypted private key
            - [ ] Opaque Private Key
    - [ ] gRPC Remote Attestation
        - [x] Verifier (Service Provider)
            - [ ] Opaque TLS Private Key
            - [x] mTLS auto-negotiation
            - [x] Get Endorsement Key Certificate
            - [x] Get Attestation Key Profile
            - [x] Make Credential Challenge
            - [x] Activate Credential
            - [x] Issue AK x509 Certificate
            - [x] Quote / Verify
            - [x] Automatic Device enrollment
        - [x] Attestor (Client)
            - [ ] Opaque TLS Private Key
            - [x] mTLS auto-negotiation
            - [x] Get Endorsement Key Certificate
            - [x] Get Attestation Key Profile
            - [x] Activate Credential
            - [x] Quote / Verify
            - [x] Automatic Device enrollment
    - [ ] Flows
        - [ ] Device Provisioning
            - [x] Auto-provision during Remote Attestation
            - [ ] Pre-provision keys and x509 device certificate
        - [ ] Service Request - Part 1: Platform Anonymous Identity Validation
        - [ ] Service Request - Part 2: Platform Software State Validation
        - [ ] Service Delivery
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
