% tpadm pkcs11 | Trusted Platform Commands Manual

# NAME

**pkcs11** - Perform PKCS #11 token operations

# SYNOPSIS

**pkcs11** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**pkcs11** - Shows library and hardware information about connected PKCS #11
Hardware Security Modules.


# OPTIONS

  * **-m**, **\--module**:

    The PKCS #11 module path
  
  * **-l**, **\--label**:

    The PKCS #11 token label, used to uniquely identify the hardware module.

  * **-s**, **\--slot**:

    The PKCS #11 token slot

  * **\--ykcs11**:

    Use the Yubico module located at /usr/local/lib/libykcs11,so

  * **\--softhsm2**:

    Use the SoftHSM2 module located at /usr/local/lib/libsofthsm2,so

  * **\--opensc**:

    Use the OpenSC module located at /usr/local/lib/opensc-pkcs11,so


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES


# EXAMPLES

## Display SoftHSM2 module information
```bash
tpadm pkcs11 --module /usr/local/lib/libsofthsm2.so
```
