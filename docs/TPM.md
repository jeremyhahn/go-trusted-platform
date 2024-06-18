# Trusted Platform Module

This document provides information on what a TPM is along with tools, tutorials,
and examples on how to work with it.



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


```
var decrypter crypto.Decrypter
decrypter = <implement this>

cert := &tls.Certificate{}
cert.<other fields>
cert.PrivateKey = decrypter

conn, err := tls.Dial("tcp", "127.0.0.1:443", &tls.Config{
	Certificates: []{cert},
})
```

#### Misc

1. Secure Boot on Raspberry PI:
   https://github.com/raspberrypi/usbboot/blob/master/secure-boot-example/README.md

2. https://security.stackexchange.com/questions/261028/tpm-use-without-secure-boot

he usual approach - used by Bitlocker and other TPM-capable volume encryption schemes - is to "seal" the volume encryption key using Platform Configuration Registers (PCRs). The encryption key (or a value used to derive it) is stored in (possibly generated in) the TPM with a policy that it can only be released if certain PCRs have their expected values. While the set of PCRs available varies somewhat, the general notion is the same in all cases: the PCRs contain a rolling hash of data that has been used by the system up to a given point in time. The first data fed into the PCRs is done during the "Core Root of Trust Measurement" or CRTM execution. The CRTM is generally non-writable code that "extends" some critical code - usually the device's low-level firmware (BIOS/UEFI on PCs and similar devices) - into one PCR, and that code's configuration data into another PCR. That code (low-level firmware) will then extend the next stage of code, such as a bootloader or minimal decryption utility, etc. into yet another PCR, and so on until you get to the main operating code. Code that has been extended into a PCR in this way is said to be "measured" by that PCR; any change to the code will result in a different value in the PCR.

Volume encryption enters this story when you generate the encryption key and store it in the TPM with a TPM policy that essentially says "the key shall only be available if the following set of PCRs have their current values". Generally, you want this to be either every PCR for the code up to the point where the decryption code would take over, or at least every PCR for the code up to the point where the measured code will itself validate cryptographic signatures on further sections, up to the decryption code. The key is thus available if - and only if - the boot process has not been tampered with. An attacker modifying the firmware, or bootloader, or decryption tool (or analogues in e.g. an embedded device without a full OS) - whether directly, or by booting from a different boot device / program - will mean the PCRs don't have the same value and render the decryption key unavailable.

Note that this process does not prevent booting an alternative system, nor does it inherently verify that the system is signed with a trusted key (although the measured code may perform such a verification, the PCRs don't know or care). Those functions are the providence of Secure Boot. Instead, this process simply ensures that the key is only released if the boot sequence, up to a certain point, is the same as it was when the key was sealed.

There are attacks against TPM-based volume encryption. First of all, you obviously need to prevent malicious code from executing once you're past the point where the decryption process unseals the key. On PCs and phones, this is the domain of the OS' security features; on an embedded device, maybe you just don't allow any method to run arbitrary code after that point is reached in the boot process. You also need to protect against direct memory access (DMA) by external systems (via e.g. Thunderbolt or PCI Express connectors, or debug interfaces on the board), either preventing DMA entirely or restricting it from reading the addresses where the decryption key lives (and from writing to any address, as that could be used to load arbitrary code that fetches and reveals the decryption key). These concerns are common across all volume encryption schemes and can't be directly prevented via Secure Boot or similar (though without Secure Boot, it might be possible to modify some non-encrypted data to take control of the system after the key is unsealed, bypassing the OS security controls).

There are also some cases where Secure Boot in connection with TPM-based encryption can directly provide more security for the encryption. For example, a "cold boot" attack is where you let the system boot normally, such that the volume encryption key is unsealed and stored in RAM to enable decrypting (and encrypting on writes) the encrypted volume. The device is then shut down and - before the RAM loses its charge - restarted with firmware that does not wipe the RAM on startup. The PCRs won't be the same, but that doesn't matter; the malicious firmware can read the plaintext key out of the RAM where it was preserved from the normal boot. This attack is a lot easier on devices that have discrete RAM, as that can be made extremely cold (using e.g. cryogenically cold liquids) to extend the powered-off lifetime of data in RAM into the minutes, and allow it to be pulled from one device and installed into another (which, if possible, totally sidesteps Secure Boot). An SoC is trickier to attack in this way, but not inherently impossible, as there's usually a way to glitch the board into restarting/loading code without wiping RAM even if that's not officially supported. However, using Secure Boot might prevent the malicious firmware from running, spoiling the cold boot attack even if the attacker can get the device to start booting without wiping or losing the decryption key from RAM.