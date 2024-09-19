# Platform Authentication

Trusted Platform Security Officer's log in via the Security Officer PIN.

Trusted Platform Administrators and/or Users perform authentication via
user PIN or WebAuthn.

Trusted Platform web service consumers authenticate using WebAuthn and
JSON Web Tokens.


#### PKCS #11

Use the platform configuration file to specify the location to the shared object
library provided by your manufacturer's Harware Security Module. The following is
an example using SoftHSM:

    # The path to the library
    library: /usr/local/lib/softhsm/libsofthsm2.so

    # The library configuration file
    config: ../../libs/configs/platform/softhsm.conf

    # The slot where the token is present
    slot: 0

    # The platform token label
    label: Trusted Platform

    # The Security Officer PIN
    # This should never be set for anything other than
    # development and testing.
    so-pin: 1234

    # The User PIN
    # This should never be set for anything other than
    # development and testing.
    pin: 5678

    # Seal the PIN to the TPM using the platform PCR policy
    platform-policy: true
