# Overview 


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

This Trusted Platform relies on Secure Boot and the TPM to record measurements that guarantee the integrity of every critical piece of firmware, drivers, and software used to boot into the Operating System.

The Trusted Platform takes over after the Operating System has booted, and extends the trusted execution environment to any application that integrates with it. The Trusted Platform provides a way for servers and clients to prove their identities, attest to operating system software states & configurations, enforce network policies, and provide secure key management to connected devices.

In addition to platform integrity, the included Certificate Authority establishes a Public Key Infrastructure (PKI) that's used to issue TLS and digital certificates for any service or device on the network.

Private keys generated and used by the Trusted Platform (and the applications that integrate with it), are managed by the Certificate Authority, which uses the TPM and/or 
[Hardware Security Modules](https://csrc.nist.gov/glossary/term/hardware_security_module_hsm) for secure private key generation and storage. 

TPM 2.0 has a true Random Number Generator (RNG), which the Certificate Authority can be configured to use during private key and signing operations (the default) instead of the random source provided by the Operating System.

The traffic between the CPU <-> TPM bus supports encryption to help protect against side-channel and other hardware based attacks.

The platform configuration file provides examples and documentation on how to tune and optimize the platform according to your desired security posture and application requirements.

### Compatibility

This project makes use of the new [go-tpm/tpm2](https://github.com/google/go-tpm) "TPMDirect" TPM 2.0 API introduced in v0.9.0.

As the complimentary [go-tpm-tools](https://github.com/google/go-tpm-tools) and [go-attestation](https://github.com/google/go-attestation) projects are using the [Legacy API](https://github.com/google/go-tpm-tools/issues/462), along with the TPM Event Log [not being completely reliable](https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md), a slightly different approach is taken for verification that bypasses this mess, and simply performs a byte level comparison of the event log and PCR state during attestation, using the event log and PCR state captured during enrollment. The captured data is signed and stored in the CA blob store where subsequent attestations are verified using the stored signature from the blobs caputured during enrollment.

Linux is the only platform being developed on and supported at this time. As Go is a portable language, it will likely run fine on Mac and Windows, however, [Windows will not support the future planned plugin architecture](https://pkg.go.dev/plugin).

Local development environment is Debian / Ubuntu. 


## Documentation

The `docs` folder provides links to resources with detailed information about how the internals of the TPM and various other components used in this project work, along with examples of how to use the software included in this repository.

As this is a work in progress, complex project, and many resources on uses cases and implementation details using the TPM are incomplete, scarce, inconsistent, old, and some just plain wrong, I will continue to update the docs to capture as much accurate and helpful information as possible, and continue to update this README to reflect the road map and current status.


## Road Map

This project aims to be FIPS compliant and follows best practices and guidance issued by the TCG and NIST to provide everything necessary to provision, manage, scale and secure a trusted service provider platform and it's clients on-prem, in the cloud, or hybrid environment.

The Trusted Platform is also supporting it's own cloud - an experimental mode, running as a globally distributed network powered by it's users, similar to Bitcoin.

The stimulus for this project is an [Agricultural IoT Platform](https://github.com/jeremyhahn/go-cropdroid) I've been working on for a few years. I'll be cherry picking code from several repositories in the "cropdroid" family, combined with new pixie dust, to create a robust, general purpose web services and IoT platform that can be used to host and secure many different types of applications and deployment scenerios, from public service providers to corporate IT systems and home networks.

The initial use case I'm supporting is a local farmers market that runs as an open, distributed network that any user can join, including hardware and software to automate physical cultivation processes and laborious tasks, provide detailed logs and data points on every aspect of the cultivation process, for example, reports on organically produced products, an integrated shopping cart system to sell harvests, and a rich ecosystem for collaboration and e-commerce, connecting farmers and organic consumers around the world. [An Android app](https://github.com/jeremyhahn/cropdroid-android) provides the ability to receive real-time alerts and notifications, monitor and control hardware devices, provide shopping cart features, and connect with and collaborate with other users on the network, including resource sharing (data replication, backups, WAN clustering / load balancing) and lots of other cool stuff.


#### TCG

1. [Trusted Platform Module Library - Part 1: Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf)

2. [Trusted Platform Module Library - Part 2: Structures](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.99.pdf)

3. [Trusted Platform Module Library - Part 3: Commands](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)

4. [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)

5. [Registry of Reserved TPM 2.0 Handles and Localities](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf)

6. [TCG TPM v2.0 Provisioning Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf#page=39&zoom=100,73,501)

7. [TCG Guidance for Securing Network Equipment Using TCG Technology](https://trustedcomputinggroup.org/wp-content/uploads/TCG_Guidance_for_Securing_NetEq_1_0r29.pdf)

8. [TCG Guidance for Secure Update of Software and Firmware on Embedded Systems](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Secure-Update-of-SW-and-FW-on-Devices-v1r72_pub.pdf)


#### NIST

1. [800-147: BIOS Protection Guidelines](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-147.pdf)

2. [800-147B: BIOS Protection Guidelines for Servers](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-147b.pdf)

3. [800-57: Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf)

4. [800-88: Guidelines for Media Sanitization](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf)


#### FIPS

1. [FIPS 140-3: Security Requirements for Cryptographic Modules](https://csrc.nist.gov/pubs/fips/140-3/final)

2. [FIPS 180-4: Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

3. [FIPS 186-5: Digital Signature Standard (DSS)](https://csrc.nist.gov/pubs/fips/186-5/finalf)

4. [FIPS 197: Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)

5. [FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf)

6. [FIPS 199: Standards for Security Categorization of Federal Information and Information Systems](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf)

7. [FIPS 200: Minimum Security Requirements for Federal Information and Information Systems](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.200.pdf)

8. [FIPS 201-3: Personal Identity Verification (PIV) of Federal Employees and Contractors](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-3.pdf)

9. [FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](https://csrc.nist.gov/pubs/fips/202/final)
