![alt text](https://github.com/jeremyhahn/go-trusted-platform/blob/main/public_html/images/logo.png?raw=true)


## Overview

The `Trusted Platform` uses a [Trusted Platform Module (TPM)](https://en.wikipedia.org/wiki/Trusted_Platform_Module), [Secure Boot](https://en.wikipedia.org/wiki/UEFI), and a provided [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) to establish a Platform Root of Trust for Storage & Reporting, perform Local and [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html), encryption, signing, x509 certificate management, data integrity, intrusion detection, licensing, device provisioning and more.

This software is intended for use by device manufacturers, enterprise administrators, platform administrators and end users to be used as `Platform Software` as described by the [Trusted Computing Group](https://trustedcomputinggroup.org/), a framework for building secure and/or "trusted" services, or a library for building custom platforms and services based on Trusted, Confidential Computing technologies.

Some use cases include:

* Private / Public / Hybrid Cloud Service Providers
* OEM Device Manufacturing
* Automated Device Provisioning
- Automated Device Fleet Management
* DevOps Automation Platform
* TCG Enterprise Admin, Platform Admin, & User operations
* Automated Certificate Management
* Enterprise Network Management
* Mobile Device Management
* Secure Key, Password & Secret Store
* Trusted Web Services Framework
* WebAuthN / FIDO2 Integration
* Single Sign-On & MFA
* PKI-as-a-Service
* OEM & Cloud Service Provider Licensing
* Digital Rights Management


For detailed documentation on the components used in this project, please refer to the [docs](docs/OVERVIEW.md).

## Build

#### Dependencies

* [Linux](https://www.debian.org/)
* [Make](https://www.gnu.org/software/make/)
* [Golang](https://go.dev/)
* [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/)

Optional dependencies:

* [SoftHSM](https://www.opendnssec.org/softhsm/)
* [NitroKey](https://www.nitrokey.com/products/nitrokeys)
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

Copy a [config file](configs/platform/config.dev.yaml) to `./config.yaml` (where you will run the `tpadm` binary). Edit the configuration file according to your environment and requirements.

The Trusted Platform will try to read the TPM Endorsement Key Certificate from NVRAM, however, not all TPM's have their certificates flashed to NVRAM. Next it will attempt to download the EK certificate from the Manufacturer website (currently only Intel is supported). If neither of these methods is able to locate your TPM EK certificate, an EK certificate will be generated. If an EK `cert-handle` is defined, the generated certificate will be written to NV RAM. It may optionally be stored in the x509 certificate store.

The development and example attestation configs uses a TPM simulator which is reset every time the platform starts. Be sure to set the simulator to false in the platform configuration file to start using your real TPM device. The included prod config file provides some example defaults intended for a production environment.


## Algorithm Safety

Selecting secure encryption and hash function algorithms, padding schemes, and cipher suites are critical to the final security posture of an application. Many algorithms and schemes that are in wide use today have been found to contain vulnerabilities. Be sure to check out the [Safe Curves](https://safecurves.cr.yp.to/) website for the latest updates on EC algorithms. The NIST recommends a minimum RSA key size of 2048 until the year 2030, however, many RSA users are already moving towards larger key sizes.

Note that many low cost HSM's don't offer RSA 4096 bit keys or Curve25519. Check your HSM documentation closely prior to purchase.

The TPM 2.0 spec does not support Curve25519, but does support ECDSA. Unfortunately, as can be seen on the Safe Curves website, many ECDSA curves used in the wild are not up to par. For the best security, I recommend preferring RSA over EC for TPM 2.0. Note that the TPM must support FIPS 140-2 to perform RSA-PSS signatures. This can be confirmed by issuing `TPM2_GetCapability` and inspecing the `TPM_PT_MODES` property, or checking the manufacturer datasheet. 

If you're looking for general guidance, EdDSA Curve25519 provides the best security by modern standards, followed by RSA (PSS) using strong keys, preferably 4096 bit. The [NitroKey 3](https://www.nitrokey.com/products/nitrokeys) is a cost effective PKCS #11 solution providing both RSA 4096 bit keys and Curve25519.


##### Web Services

The platform includes a built-in web server to host the REST API. The provided configuration files start the web server on HTTP port 8080 and TLS port 8443. The OpenAPI docs can be browsed at `https://localhost:8443/swagger`.


Procedure to start the embedded web services for the first time:

    # Copy a config file to the local directory
    cp configs/platform/config.prod.yaml config.yaml

    # Run web services
    ./tpadm webservice

    # Navigate to OpenAPI docs
    xdg-open https://localhost:8443/swagger/



##### Key Stores

The Trusted Platform currently includes PKCS #8, PKCS #11 and TPM 2.0 key store modules. All 3 of these modules may be used at the same time.

There are a few important concepts to understand regarding the key stores. 

The first is the `Platform Key Store`, the general purpose key store that acts as a central repository for key store module PINs, secondary key passwords and generic passwords and secrets stored by the platform software (this software).

The second is the `Keychain`, which is a collection of `Key Store Module` configurations, and the keys that belong to each store.

A Keychain may be configured with any or all of the supported Key Store Modules, and must contain a valid configuration for any keys referncing that particular module.

Each Certificate Authority has it's own keychain and keys. The PIN / password for the Key Store Modules, if enabled with a `platform-policy`, are stored in the general purpose `Platform Key Store` and automatically retrieved by the Trusted Platform as necessary using a PCR policy session which releases the passwords from the TPM as long as the chosen `Platform PCR` is in it's expected well-known state.


##### Passwords

The PKCS #8 and TPM 2.0 key store modules support secondary key passwords. 

These passwords, if configured with the `platform-policy` attribute, are stored in the *Platform Key Store*, and automatically retrieved by the Trusted Platform as necessary using a PCR policy session which releases the password as long as the chosen platform PCR is in it's expected well-known state. If `platform-policy` is not set, the password will not be stored, and in the case of PKCS #8 and TPM 2.0, will require the password entered when necessary.

PKCS #11 does not support secondary key passwords.

Specifying the *default password* of `123456` for a key's password or secret attributes, will result in an auto-generated 32 byte, 256 bit password or secret.

    If a `platform-policy` attribute is not set for the key, it's password will need to be manually entered anytime an operation that requires it's password is performed.


## LUKS

At this time, preliminary support for LUKS is included in the `Makefile`. In the future, full LUKS integration will be provided through the platform software.

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

Upon startup, the TPM is initialized according to the platform configuration file. A minimum configuration requires EK and SSRK TPM key attributes defined. The [IEEE 802.1AR Secure Device Identity](https://1.ieee802.org/security/802-1ar/) and [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf) specifications RECOMMEND also provisioning devices with an IAK & IDevID certificate, and as such, is included in the default configuration file. These keys, however, can be omitted for minimal provisioning, for example, if you're only using the TPM for a local secure key or password store, and not interested in any attestation features.

When the platform starts up, the `Local Certificate Authorities` are initialized, resulting in a Root and Intermediate CA with public / private keys and signing certificates for each of the keys listed in the platform configuration file. The Intermediate CA will have the Root certificate imported to its trusted root store. A Certificate Revocation List is created and initialized with a dummy certificate for each of the configured key algorithms, in each of the configured Key Store Modules. The local Certificate Authority is also exposed as an ACME server, which allows the platform to operate as an Enterprise or Privacy CA, depending on how the configuration provided to the platform software at startup. See the [server](configs/platform/config.debug.server.yaml) and [client](configs/platform/config.debug.client.yaml) examples on starting the platform as a client or server.

After the CA is initialized, local system platform measurements are taken according to the platform configuration file, signed by the CA, and placed into internal blob storage, along with the digest, signature, and checksum of the measurements. On subsequent startups and/or ongoing timer basis, new system measurements are taken, a new digest is created and verified against the initial platform measurements. If the signature does not match (the state is different / unexpected), the platform will return a fatal error and terminate. In the future, it will also integrate with LUKS volumes and run a set of custom event handlers that allow responding to the unexpected state of the system using a plugin architecture, to perform operations such as re-sealing the platform, unmounting sensitive volumes, notifying intrusion detection and/or monitoring systems, etc.

If an ACME client configuration is enabled in the platform configuration file, the platform will start in "client mode", where it contacts the ACME server endpoint specified in the configuration to perform an automatic device enrollment using custom `endorse-01` and `device-01` challenges to enroll the device with the Enterprise / Privacy CA. After successful enrollment, the platform and TPM will be fully provisioned with an EK, IAK, and IDevID keys and certificates issued by the Enterprise CA. The platform will be ready to fulfill future network device authentication and attestation requirements defined by the Enterprise Administrator, as well as request TLS certificates for public web services. As such, the ACME client requests a final TLS certificate from the Enterprise / Privacy ACME server for the embedded web server, and upon successful completion of the configured challenge, the TLS certificate is issued and automatically configured for the embedded web server, and the platform is started and ready to begin answering web service requests or making authenticated client requests for resources on the network.


## Remote Attestation

A remote attestation implementation using the procedure outlined by [tpm2-community](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html) is working, however, be sure to read the notes in the [attestation](pkg/attestation) directory regarding this approach. This will be replaced with an ACME device-attest enrollment protocol in the near future.

To test it out using the provided `Makefile` targets.

    # Attestor
    make attestor

    # Verifier
    make verifier

After attestation completes, you should see a new `attestation` folder appear that looks something like the exaample below (on the verifier side):

This example demonstrates a Certificate Authority with PKCS #8, PKCS #11, and TPM 2.0 key store modules configured with RSA (PSS), ECDSA and Ed25519 keys configured to enable simultaneous signing with any of the configured keys. In addition, PKCS #8 and TPM 2.0 keys support secondary password protection, using key level passwords in addition to the PIN used to secure the keys at the hardware level. The passwords are stored in the *Platform Key Store* as HMAC secrets with an optional PCR policy that allows retrieval of the password as long as the platform is in it's approved state. The key store PINs have the `.pin` extension in their file names, while secondary passwords are stored using only their common names.

Note that the TPM 2.0 spec does not support Twisted Edward Curves (Ed25519). Many budget friendly HSM's also don't support twisted curves. Be sure to check the specifications on your HSM and to confirm support.

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

The current list of intended features and their status are shown below.


- [ ] Trusted Platform
    - [ ] Certificate Authority
        - [x] Automated Certificate Management Environment (ACME)
            - [x] RFC 8555 compliant server
            - [x] RFC 8555 compliant client
            - [x] Supported Challenges
                - [x] [http-01](https://datatracker.ietf.org/doc/html/rfc8555)
                - [x] [dns-01](https://datatracker.ietf.org/doc/html/rfc8555)
                - [x] [device-attest-01](https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03)
                - [x] http-x (custom - http-01 w/ configurable port)
                - [x] endorse-01 (custom - Issue EK cert)
                - [x] device-01 (custom - TCG-CSR-IDEVID device enrollment)
            - [x] Cross-Signed Certificates (Let's Encrypt or any ACME server)
        - [x] Key Storage Modules
            - [x] [PKCS 8](https://en.wikipedia.org/wiki/PKCS_8)
            - [x] [PKCS 11](https://en.wikipedia.org/wiki/PKCS_11)
            - [x] [TPM 2.0](https://en.wikipedia.org/wiki/Trusted_Platform_Module)
            - [x] [SoftHSM](https://www.opendnssec.org/softhsm/)
        - [x] Key Storage Backends
            - [x] File storage
            - [x] PKCS 11
            - [x] TPM 2.0
            - [x] SoftHSM
            - [ ] [Raft](https://raft.github.io/)
        - [x] Formats
            - [x] [PKCS 1](https://en.wikipedia.org/wiki/PKCS_1)
            - [x] [PKCS 8](https://en.wikipedia.org/wiki/PKCS_8)
            - [x] [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
        - [x] [TLS 1.3](https://words.filippo.io/tls-1-3-at-33c3/)
        - [x] Root CA
        - [x] Intermediate CA(s)
        - [x] RSA, ECDSA & EdDSA Key Algorithms
        - [x] Simultaneous issue/sign/verify using any supported algorithm and key store
        - [x] Certificate & Key storage & retrieval
        - [x] Private trusted root & intermediate certificate store
        - [x] Distinct CA, TLS, Device encryption & signing keys
        - [x] RSA, ECDSA, Ed21159 & x25519Kyber768Draft00 support
        - [x] Create & Sign Certificate Signing Requests (CSR)
        - [x] Generate, Sign & Verify TCG-CSR-IDEVID
        - [ ] Generate, Sign & Verify TCG-CSR-LDEVID
        - [x] x509 Certificate Revocation Lists (CRLs)
            - [ ] Web service endpoint
        - [x] Encoding & Decoding support for DER and PEM
        - [x] Automatic download & import Issuer CA(s) to trust store
        - [x] Automatic download & import Revocation Lists (CRLs)
        - [x] Create & Parse CA bundles
        - [x] Create Golang CertPool objects pre-initialized with CA certificates
        - [x] Create Golang tls.Config objects pre-initialized for mTLS
        - [x] Signed blob storage
        - [x] Install / Uninstall CA certificates to Operating System trust store
        - [x] Generate TCG compliant EK certificate
        - [x] Generate Attestation Key Certificate
        - [x] Forge Certificates (force specified public key)
    - [x] ACME Client
    - [ ] TPM 2.0
        - [x] Provisioning per TCG recommended best practices
        - [x] Read Endorsement Key Certificate from NVRAM
        - [x] Download Endorsement Key Certificate from Manufacturer
            - [x] Intel
            - [ ] Infineon
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
    - [ ] DNS Server
        - [x] Public zones
        - [x] Internal zones
        - [x] Zone registration via ACME dns-01
        - [ ] DNSSec w/ Opaque keys
    - [ ] DNS client
        - [ ] Dynamic DNS updates
    - [ ] Web Services
        - [x] HTTP/1, HTTP/2, HTTP/3
        - [x] Transport Layer Security (TLS)
            - [x] TLS 1.3 only
            - [x] Opaque private keys
            - [x] mTLS
        - [x] WebAuthn
            - [x] Begin Registration
            - [x] Finish Registration
            - [x] Begin Login
            - [x] Finish Login
        - [x] JSON Web Tokens
            - [x] Generate Token
            - [x] Refresh Token
            - [x] Validate Token
            - [x] Encrypted private key
            - [x] Opaque Private Key
        - [x] REST API
            - [x] Swagger / OpenAPI Docs
            - [ ] Service Plugin Architecture
        - [x] Rewrite rules
        - [x] Reverse proxy
        - [x] Virtual Hosts
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
    - [ ] Password & Secrets Manager
        - [ ] CLI
        - [ ] Web Service
        - [ ] gRPC Service
    - [ ] Platform Plugin Architecture
        - [ ] Build and publish
        - [ ] Install / uninstall
        - [ ] Sign / verify
    - [ ] Volume Encryption (LUKS)
        - [x] Preliminary Luks support (Makefile)
        - [ ] Full LUKS integration to create and manage volumes
    - [ ] Automated Setup and Provisioning
        - [ ] Trusted Platform
            - [ ] PXE Boot
            - [ ] Bare Metal (ISO)
            - [ ] Raspberry PI (SD Image)
            - [ ] Docker
            - [ ] Kubernetes
            - [ ] Amazon Web Services
            - [ ] Google Cloud
            - [ ] Azure
        - [ ] NetOps (Routing, Switching, Firewalling, Load Balancing, VPN)
            - [ ] Cisco Application Centric Infrastructure (ACI)
            - [ ] VyOS
            - [ ] AWS VPC
            - [ ] Google Cloud VPC
            - [ ] Azure VPC
        - [ ] Configuration Management
            - [ ] Ansible
        - [ ] Embedded Systems
            - [ ] [Raspberry PI](https://www.raspberrypi.com/)
                - [ ] Image builder
                    - [ ] Secure Boot
                    - [ ] One-Time Programmable Memory
                    - [ ] SD Card Writer
                    - [ ] Device Provisioning
                    - [ ] Device Onboarding
                - [x] Ansible system configuration
            - [ ] [Arduino](https://www.arduino.cc/en/hardware)
                - [ ] ROM integrity check
                - [ ] Platform firmware
                - [ ] Firmware flasher
                - [ ] Device Provisioning
                - [ ] Device Onboarding
            - [x] FPGA Accelerators
                - [x] [AMD KR-260](https://www.amd.com/en/products/system-on-modules/kria/k26/kr260-robotics-starter-kit.html)
            - [ ] AI Machine Learning
                - [ ] [Google Coral TPU](https://coral.ai/products/)
    - [ ] Continuous Integration & Delivery
        - [ ] Git Integration
            - [ ] Build Arbitrary Repos
            - [ ] Code Signing
            - [ ] Automated Deployments
        - [ ] Over-the-air Updates
    - [ ] Peer-to-Peer Networking
        - [ ] [libp2p](https://libp2p.io/)
        - [ ] [OpenThread](https://openthread.io/)
    - [ ] High Availability
        - [ ] Gossip [(Partition Tolerance & Availability)](https://en.wikipedia.org/wiki/CAP_theorem)
            - [ ] Real-time platform network statistics
            - [ ] Health checking and monitoring
            - [ ] WAN Database Replication
            - [ ] Automated provisioning event system
        - [ ] Raft [(Consistency & Availability)](https://en.wikipedia.org/wiki/CAP_theorem)
            - [ ] Datastore Replication
            - [ ] Key replication
    - [ ] Intrusion Detection
        - [x] File Integrity Monitoring
        - [ ] Detect unauthorized software or hardware changes
        - [ ] Tamper Resistance
            - [ ] Pluggable event based response mechanisms
                - [ ] Platform shutdown
                - [ ] Unmount luks container (re-sealing the platform)
                - [ ] Delete luks volume & platform binary
                - [ ] Wipe file system
    - [ ] Data Vaults
        - [ ] Data storage
            - [ ] Local
            - [ ] IPFS
            - [ ] S3
            - [ ] ...
        - [ ] Encryption & Signing
        - [ ] Share w/ Digital Rights Management
    - [ ] Monetization Features
        - [ ] [Stripe](https://stripe.com/) Integration
        - [ ] Data Vaults
        - [ ] Web Service Endpoints
        - [ ] Platform & Device Licensing
    - [ ] Blockchain & Smart Contract Integration
        - [ ] [Ethereum](https://ethereum.org/en/)
        - [ ] [Tangle](https://www.iota.org/get-started/what-is-iota)



## Sponsors

|  |  |
| ------- | ----- |
| <img src="https://www.nitrokey.com/sites/all/themes/nitrokey/logo.svg" width="64">| Thanks for 3 NitroKey HSM 2 devices to assist in PKCS #11 & Raft development! |


## Support

A [Discord server](https://discord.gg/TuJex32b) has been created for community support.

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn
