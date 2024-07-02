![alt text](https://github.com/jeremyhahn/go-trusted-platform/blob/main/logo.png?raw=true)


The `Trusted Platform` uses a [Trusted Platform Module (TPM)](https://en.wikipedia.org/wiki/Trusted_Platform_Module), [Secure Boot](https://en.wikipedia.org/wiki/UEFI), and a provided [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) to establish a Platform Root of Trust, perform Local and [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html), encryption, signing, x509 certificate management, data integrity, intrusion detection, licensing and more.


## Components

The main components of this project are:

### Trusted Platform Module

The Trusted Platform Module (TPM) technology is designed to provide hardware-based,
security-related functions. A TPM chip is a secure crypto-processor that is designed
to carry out cryptographic operations. The chip includes multiple physical security
mechanisms to make it tamper-resistant, where malicious software is unable to tamper
with the security functions of the TPM. 

The Trusted Platform Module (TPM) provides:

- A hardware random number generator

- Facilities for the secure generation of cryptographic keys for limited uses

- Remote attestation: Creates a nearly unforgeable hash key summary of the hardware and software configuration. One could use the hash to verify that the hardware and software have not been changed. The software in charge of hashing the setup determines the extent of the summary

- Binding: Data is encrypted using the TPM bind key, a unique RSA key descended from a storage key. Computers that incorporate a TPM can create cryptographic keys and encrypt them so that they can only be decrypted by the TPM. This process, often called wrapping or binding a key, can help protect the key from disclosure. Each TPM has a master wrapping key, called the storage root key, which is stored within the TPM itself. User-level RSA key containers are stored in a user profile for a particular user and can be used to encrypt and decrypt information for applications that run under that specific user identity

- Sealed storage: Specifies the TPM state for the data to be decrypted (unsealed)

- Other Trusted Computing functions for the data to be decrypted (unsealed)

Computer programs can use a TPM for the authentication of hardware devices, since each TPM chip has a unique and secret Endorsement Key (EK) burned in as it is produced. Security embedded in hardware provides more protection than a software-only solution. Its use is restricted in some countries.

##### Key Features and Benefits

* High-end security controller with advanced cryptographic algorithms implemented in hardware (e.g. RSA & ECC256, SHA-256)
* Common Criteria (EAL4+) and FIPS security certification
* Flexible integration (SPI, I2C or LPC interface support)
* Reduced risk based on proven technology
* Fast time to market through concept reuse
* Easy integration into all platform architectures and operating systems (Windows, Linux & derivatives)

##### Use Cases

* Automatic device onboarding
* Device health attestation
* Device identity for network access control
* Secret (configuration data, IP, and etc) protection
* Secured communication with TLS
* Secured firmware update
* Secured key storage
* Verification of device authenticity
* Licensing


### Secure Boot

The UEFI specification defines a protocol known as Secure Boot, which can secure the boot process by preventing the loading of UEFI drivers or OS boot loaders that are not signed with an acceptable digital signature. The mechanical details of how precisely these drivers are to be signed are not specified. When Secure Boot is enabled, it is initially placed in "setup" mode, which allows a public key known as the "platform key" (PK) to be written to the firmware. Once the key is written, Secure Boot enters "User" mode, where only UEFI drivers and OS boot loaders signed with the platform key can be loaded by the firmware. Additional "key exchange keys" (KEK) can be added to a database stored in memory to allow other certificates to be used, but they must still have a connection to the private portion of the platform key. Secure Boot can also be placed in "Custom" mode, where additional public keys can be added to the system that do not match the private key.

Secure Boot is supported by Windows 8 and 8.1, Windows Server 2012 and 2012 R2, Windows 10, Windows Server 2016, 2019, and 2022, and Windows 11, VMware vSphere 6.5 and a number of Linux distributions including Fedora (since version 18), openSUSE (since version 12.3), RHEL (since version 7), CentOS (since version 7), Debian (since version 10), Ubuntu (since version 12.04.2), Linux Mint (since version 21.3)., and AlmaLinux OS (since version 8.4). As of January 2024, FreeBSD support is in a planning stage.

### Certificate Authority

In cryptography, a certificate authority or certification authority (CA) is an entity that stores, signs, and issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party—trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 or EMV standard. 


## Architecture

This Trusted Platform relies on secure boot and the TPM to record measurements that guarantee the integrity of every critical piece of firmware, drivers, and software used to boot into the Operating System.

The Trusted Platform takes over after the Operating System has booted, and extends the trusted execution environment to any application that integrates with it. The Trusted Platform provides a way for servers and clients to prove their identities, attest to operating system and software states / configurations, enforce network policies, and provide secure key management to connected devices.

In addition to platform integrity, the included Certificate Authority establishes a Public Key Infrastructure (PKI) that's used to issue TLS and digital certificates for any service / device on the network.

Private keys generated and used by the Trusted Platform and the applications that integrate with it, are delegated to the Certificate Authority, which relies on the TPM for secure private key generation and storage. In addition, the TPM has a true random generator, which the Certificate Authority can be configured to use during certificate generation (the default mode) instead of the random source provided by the Operating System.

The traffic between the CPU <-> TPM bus can also be encrypted to help protect against side-channel and hardware based attacks.

The default configuration for the Trusted Platform is "use the most secure configuration possible". Use the configuration file to tune and optimize the platform.

##### Flow

The following steps are used to complete device registration, identity validation, platform software state validation, and service delivery.

###### Device Registration

![Device Registration](https://tpm2-software.github.io/images/tpm2-attestation-demo/registration.png)

###### Service Request - Part 1: Platform Anonymous Identity Validation

![Service Request - Part 1](https://tpm2-software.github.io/images/tpm2-attestation-demo/identity-validation.png)

###### Service Request - Part 2: Platform Software State Validation

![Service Request - Part 2](https://tpm2-software.github.io/images/tpm2-attestation-demo/software-state-validation.png)

###### Service Delivery

![Service Delivery](https://tpm2-software.github.io/images/tpm2-attestation-demo/service-delivery.png)


### Compatibility

This project makes use of the new [go-tpm/tpm2](https://github.com/google/go-tpm) "TPMDirect" TPM 2.0 API introduced in v0.9.0.

As the complimentary [go-tpm-tools](https://github.com/google/go-tpm-tools) and [go-attestation](https://github.com/google/go-attestation) projects are using the [Legacy API](https://github.com/google/go-tpm-tools/issues/462), I've forked the necessary code with the intention to make as much use of the original libraries as possible, replacing Legacy API calls with the new TPMDirect API, to reduce the resulting binary size and provide a consistent execution path through the libraries to the TPM.

When the go-tpm-tools and go-attestation libraries catches up to the latest go-tpm/tpm2 TPMDirect API, the forked code in this repo will be replaced with the latest versions of those libraries.

Linux is the only platform being developed on and supported at this time. As Go is a portable language, it will likely run fine on Mac and Windows, however, [Windows will not support the future planned plugin architecture](https://pkg.go.dev/plugin).

## Documentation

The `docs` folder provides links to resources with detailed information about how the internals of the TPM and various other components used in this project work, along with examples of how to use the software included in this repository.

As this is a work in progress, and complex project, I will continue to update the docs to capture as much information on relevant topics as possible, and continue to update this README to reflect the road map and current status of features.


## Road Map

This project aims to follow best practices and guidance issued by the TCG and NIST to provide everything necessary to provision, manage and run a trusted computing platform on Linux at scale, either on-prem or in the cloud:


#### TCG

1. [TCG TPM v2.0 Provisioning Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf#page=39&zoom=100,73,501)

2. [TCG Guidance for Securing Network Equipment Using TCG Technology](https://trustedcomputinggroup.org/wp-content/uploads/TCG_Guidance_for_Securing_NetEq_1_0r29.pdf)

3. [TCG Guidance for Secure Update of Software and Firmware on Embedded Systems](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Secure-Update-of-SW-and-FW-on-Devices-v1r72_pub.pdf)


#### NIST

1. [BIOS Protection Guidelines](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-147.pdf)

2. [BIOS Protection Guidelines for Servers](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-147b.pdf)


#### FIPS

1. [Security Requirements for Cryptographic Modules](https://csrc.nist.gov/pubs/fips/140-3/final)


## Status

This project is under active development. APIs can change at any moment.

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
        - [x] x509 Certificates (RSA & ECC )
        - [x] Certificate & Key storage & retrieval
        - [x] Private trusted root certificate store
        - [x] Private trusted intermediate certificate store
        - [x] Distinct TLS, encryption & signing keys
        - [x] RSA public / private keys
        - [x] RSA & ECC signing keys
        - [x] Create & Sign Certificate Signing Requests (CSR)
        - [x] x509 Certificate Revocation Lists (CRLs)
        - [x] Encoding / Decoding support for DER and PEM
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
        - [ ] Quote / Verify
    - [ ] Command Line Interface
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
        - [ ] Full Remote Attestation
            - [ ] Server (Attestor)
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
            - [ ] Client (Verifier)
                - [x] Auto-negotiated mTLSv1.3
                - [x] Get Endorsement Key (EK) and Certificate
                - [x] Get Attestation Key Profile (EK, AK, AK Name)
                - [x] Credential Challenge (TPM2_MakeCredential)
                - [x] Activate Credential ((TPM2_ActivateCredential)
                - [x] Issue Attestation Key Certificate
                - [ ] Verify Quote
    - [ ] Web Services
        - [x] Web server
        - [x] REST API
            - [x] Swagger API Docs
        - [ ] JWT Authentication
            - [x] Generate Token
            - [x] Refresh Token
            - [x] Validate Token
            - [ ] Opaque TLS Private Key
        - [x] HTTPS / TLS
        - [ ] mTLS
    - [ ] gRPC Remote Attestation
        - [x] Verifier (Service Provider)
            - [ ] Opaque TLS Private Key
            - [x] mTLS auto-negotiation
            - [x] Get Endorsement Key Certificate
            - [x] Get Attestation Key Profile
            - [x] Make Credential Challenge
            - [x] Activate Credential
            - [x] Issue AK x509 Certificate
            - [ ] Quote / Verify
        - [x] Attestor (Client)
            - [ ] Opaque TLS Private Key
            - [x] mTLS auto-negotiation
            - [x] Get Endorsement Key Certificate
            - [x] Get Attestation Key Profile
            - [x] Activate Credential
            - [ ] Quote / Verify
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
