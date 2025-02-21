# Secure Boot

UEFI Secure Boot (SB) is a verification mechanism for ensuring that code launched by a computer's UEFI firmware is trusted. It is designed to protect a system against malicious code being loaded and executed early in the boot process, before the operating system has been loaded.

SB works using cryptographic checksums and signatures. Each program that is loaded by the firmware includes a signature and a checksum, and before allowing execution the firmware will verify that the program is trusted by validating the checksum and the signature. When SB is enabled on a system, any attempt to execute an untrusted program will not be allowed. This stops unexpected / unauthorised code from running in the UEFI environment.

![Secure Boot Flow](assets/secureboot-flow.svg?raw=true "Secure Boot Flow")

# Concepts

The following concepts are required when working with Secure Boot:


## Unified Extensible Firmware Interface (UEFI)

UEFI firmware is a replacement for the Basic Input/Output System (BIOS) firmware interface. In the Secure Boot context, it has a platform key (PK) and several SB databases that include the signature database (db), revoked signatures database (dbx), and Key Enrollment Key database (KEK).

#### What does UEFI do?

    - Provides a standardized interface between the OS and firmware
    - Enables features and functionalities during the boot process 
    - Provides a standard environment for booting an OS and running pre-boot applications 
    
#### How does UEFI compare to BIOS? 

UEFI is a modern replacement for the traditional basic input/output system (BIOS) firmware

    - UEFI is compatible with BIOS
    - UEFI is expected to eventually replace BIOS

#### Why was UEFI developed? 

The original motivation for UEFI was to address limitations of BIOS, such as 16-bit real mode and 1 MB addressable memory space

#### How is UEFI managed? 

The Unified Extended Firmware Interface Forum manages UEFI as an industry-wide standard


## Secure Boot Keys

- **Platform Key (PK)** - The PK is the top-level key in Secure Boot, and it serves a function relative to the KEK similar to that of the KEK to the db and dbx. UEFI Secure Boot supports a single PK, which is generally provided by the motherboard manufacturer. Thus, only the motherboard manufacturer has full control over the computer. An important part of controlling the Secure Boot process yourself is to replace the PK with your own version.

- **Key Exchange Key (KEK)** — The KEK is used to sign keys so that the firmware accepts them as valid when entering them into the database (either the db or the dbx). Without the KEK, the firmware would have no way of knowing whether a new key was valid or was being fed by malware. Thus, in the absence of the KEK, Secure Boot would either be a joke or require that the databases remain static. Since a critical point of Secure Boot is the dbx, a static database would be unworkable. Computers often ship with two KEKs, one from Microsoft and one from the motherboard manufacturer. This enables either party to issue updates.

- **Database Key (db)** — This is the key type that you're most likely to think of with respect to Secure Boot, because it's used to sign or verify the binaries (boot loaders, boot managers, shells, drivers, etc.) that you run. Most computers come with two Microsoft keys installed. Microsoft uses one of these itself and uses the other to sign third-party software, such as Shim. Some computers also come with keys created by the computer manufacturer or other parties. Canonical (the creator of the Ubuntu Linux distribution) arranged for its key to be embedded in some computers' firmwares beginning early in the 2010s, for instance. As this description implies, the db can hold multiple keys—an important fact for some purposes. Note that the db can contain both public keys (which are matched to private keys that can be used to sign multiple binaries) and hashes (which match individual binaries). For the most part, this document focuses on the db as a carrier for keys, but you can add hashes to your db if you like. (The KeyTool program is useful for this purpose.)

- **Forbidden Signature Key (dbx)** — The dbx is a sort of anti-db; it contains keys and hashes that correspond to known malware or otherwise undesirable software. I don't describe setting up the dbx on this page, although you could install keys or hashes to it just as you would to the db. If a binary matches a key or hash that's in both the db and the dbx, the dbx should take precedence. This enables blocking a single binary (via its hash) even if that binary is signed by a key that you don't want to revoke because it's been used to sign lots of legitimate binaries.

- **Machine Owner Key (MOK)** — A MOK is equivalent to a db key; it's used to sign boot loaders and other EFI executables or to store hashes corresponding to individual programs. MOKs are not a standard part of Secure Boot, though; they're used by the Shim and PreLoader programs to store keys and hashes. As such, this page doesn't cover them in any detail.


#### Lockdown Options

It's worth considering precisely how you intend to lock down your computer. Broadly speaking, you have three options:

- **Extreme self-reliance** — You can rely exclusively on your own keys, which means you must sign every program your firmware runs, and probably sign every Linux kernel you boot. This is an extreme solution that's likely to be tedious to maintain; but if you secure your private keys well, it can provide excellent security.

- **Trusting some third parties** — You can add third-party keys to your db, which will enable binaries signed by that party to run without modification. You might do this to simplify maintenance of a distribution such as Fedora, OpenSUSE, or Ubuntu, all of which distribute signed copies of GRUB and of their Linux kernels. Similarly, you might add one or both of Microsoft's public keys if you want to run Windows or third-party programs signed by Microsoft's key. (Note that plug-in cards may have firmware that's been signed by Microsoft's third-party key.) On the other hand, relying on these keys will render your computer at least theoretically vulnerable to attack should their private keys be compromised or should bugs, such as Boot Hole, be discovered in software signed by them. Because GRUB 2 flaws are likely to be handled via Shim's SBAT mechanisms moving forward, launching GRUB 2 without Shim is becoming a bit risky.

- **Hybrid with Shim** — You can take partial or complete control of your Secure Boot keys by using your own PK, KEK, and perhaps db keys, and optionally add Microsoft's db keys as well; but rely on Shim (signed with Microsoft's keys or your own) to add its built-in keys with which to launch Linux. This approach gives you significant control over your computer, while also enabling use of Shim's SBAT extensions, which are described later, in Revoking Keys and Hashes.


The Trusted Platform provides a toolset and framework that supports the _extreme self-reliance_ option, and is the reference architecture for running the Trusted Platform itself.


## Shim

Shim is a small program that acts as a first-stage bootloader, primarily used in conjunction with UEFI Secure Boot, where it verifies the digital signature of the next bootloader (like GRUB) before loading it, ensuring only trusted bootloaders can be executed on the system; essentially acting as a bridge between the UEFI firmware and the main bootloader, verifying its authenticity before launching it. 

Key points about Shim:


#### Secure Boot

Shim is crucial for enabling Secure Boot on Linux systems, where the UEFI firmware checks the digital signature of the bootloader before allowing it to run. 

#### Verification

When a system boots with Secure Boot enabled, the UEFI firmware first loads and verifies the signature of the "shim" program, which then verifies the signature of the next stage bootloader (like GRUB) before launching it.

#### Trust chain

Shim acts as a "root of trust" by embedding a certificate from a trusted authority (like Microsoft) which allows it to verify the signatures of other boot components. 

#### Open-source

Shim is developed by a collaborative effort between different Linux distributions, ensuring a common and well-audited piece of code. 


# Related

[Building a Trusted Platform ISO](ISO.md)


# References

https://wiki.debian.org/SecureBoot

https://www.rodsbooks.com/efi-bootloaders/controlling-sb.html

https://www.linuxjournal.com/content/take-control-your-pc-uefi-secure-boot

https://wiki.gentoo.org/wiki/Secure_Boot/GRUB

https://media.defense.gov/2023/Mar/20/2003182401/-1/-1/0/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20230317.PDF
