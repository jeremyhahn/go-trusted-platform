# Trusted Platform Module

This document provides information on what a TPM is along with tools, tutorials,
and examples on how to work with it.


   Using the Trusted Platform Module in the New Age of Security

[A Practical Guide to TPM 2.0](https://link.springer.com/book/10.1007/978-1-4302-6584-9)


## What is a TPM?

1. https://www.infineon.com/cms/de/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm/

2. https://community.infineon.com/t5/Blogs/What-is-a-TPM-What-is-it-used-for/ba-p/396224

3. https://community.infineon.com/t5/Blogs/Securely-store-your-credentials-and-cryptographic-keys-in-TPM2-0/ba-p/408020

4. https://community.infineon.com/t5/Blogs/Storing-and-reporting-system-measurements-with-TPM/ba-p/443590

5. https://community.infineon.com/t5/Blogs/TPM-remote-attestation-How-can-I-trust-you/ba-p/452729


https://en.wikipedia.org/wiki/Trusted_Platform_Module

https://uefi.org/sites/default/files/resources/UEFI_Plugfest_Advanced_TPM_Usage_Fall_2018.pdf


1. https://dev.to/nandhithakamal/tpm-part-1-4emf

2. https://dev.to/nandhithakamal/how-to-tpm-part-2-55ao

3. https://github.com/tpm2dev/tpm.dev.tutorials/blob/master/Intro/README.md


## Tutorials

https://tpm2-software.github.io/tutorials/

https://tpm2-software.github.io/2020/06/12/Remote-Attestation-With-tpm2-tools.html

https://joholl.github.io/tpm2-tools/tutorial/2019/10/09/Tools-Tutorial.html



## Libraries

Developer community for those implementing APIs and infrastructure from the TCG TSS2 specifications.

https://github.com/tpm2-software

Go-TPM is a Go library that communicates directly with a TPM device on Linux or Windows machines.

https://github.com/google/go-tpm

Go-Attestation abstracts remote attestation operations across a variety of platforms and TPMs, enabling remote validation of machine identity and state. This project attempts to provide high level primitives for both client and server logic.

https://github.com/google/go-attestation


Attest the trustworthiness of a device against a human using time-based one-time passwords

https://github.com/tpm2-software/tpm2-totp



## Tools

The source repository for the Trusted Platform Module (TPM2.0) tools.

https://github.com/tpm2-software/tpm2-tools


The go-tpm-tools module is a TPM 2.0 support library designed to complement Go-TPM.

https://github.com/google/go-tpm-tools


Use a TPM to store a TOTP token in order to attest boot state to another device

https://github.com/mjg59/tpmtotp



## Examples

https://github.com/salrashid123/tpm2

https://github.com/salrashid123/signer/blob/master/tpm/tpm.go

https://github.com/salrashid123/go_tpm_https_embed

https://blog.salrashid.dev/articles/2022/golang-jwt-signer/



## References

https://tpm2-software.github.io/software/

https://pkg.go.dev/crypto#Signer

https://pkg.go.dev/crypto/rsa#PrivateKey.Sign

https://pkg.go.dev/crypto#Decrypter

https://pkg.go.dev/crypto/rsa#PrivateKey.Decrypt



## Endorsement Keys

* [TCG EK Credential Profile] https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf



#### Misc

1. Secure Boot on Raspberry PI:
   https://github.com/raspberrypi/usbboot/blob/master/secure-boot-example/README.md

2. https://security.stackexchange.com/questions/261028/tpm-use-without-secure-boot
