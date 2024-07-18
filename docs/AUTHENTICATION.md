# Platform Authentication

Trusted Platform administrators perform authentication via the
Certificate Authority.

When the platform starts up, the configuration file is inspected for
the presence of a PKCS #11 module. If not defined, a PKCS #8 key store
is created.


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


#### PKCS #8

2 passwords are required to setup and subsequently access the platform. The
Root password is used to password protect the Root Certifiate Authority Private
Key. The operator password is used to password protect the first Intermediate Certifiate Authority that is created by default, during platform setup. After
setup, the Root Certificate Authority Private Key should be removed from the
system and the CA taken offline. Future operations should be performed using
an Intermediate Certificate Authority, either the default created during setup,
or an additional created afterwards.

Passwords should never be set in the platform configuration file while in a
production environment, however, can be useful during testing and development.

Use the `key-password` property for the Certificate Authority Identity to set the
password in the configuration file.
