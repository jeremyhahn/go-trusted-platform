# tpm2-software procedure

This Verifier & Attestor package uses the [Remote Attestation procedure](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html) described by tpm2-software, returned as a top search result when inquiring on the subject.

![Key Provisioning](https://tpm2-software.github.io/images/diag1.png)

# READ THIS FIRST!

*IMHO, this is incorrect!* Don't do this unless you've thought through your entire enrollment and provisioning process and are certain this example is the best solution.

1. TCG TPM 2.0 Keys for Device Identity and Attestation states the following:

    ##### Section 6.1.1 Requirements
    Software under control of the OEM MUST be able to create keys as described in section 3.6, retrieve the TPM’s EK certificate. *The software must be able to securely create and sign a TCG-CSR-IDEVID (refer to section 13.1).*

This flow does not mention anything about TCG-CSR-IDEVID or provide any mechanisms for generating the CSR or submitting it to the Verifier during provisioning. It only specifies an EK pub, AK pub and AK name, returned as an "AK Profile".

This deviates from the TCG and IEEE 802.1 AR specifications, which also require a unique product model, serial number and permanent identifier, in addition to other TCG specific OIDs for hardware module type, etc.

In addition, there is no signing algorithm provided in the AK profile, which means either hard-coding it on both the Attestor and Verifier, or modifying the structure of the AK Profile. This does not fit well with the Trusted Platform CA which supports multiple key & signature algorithms.

2. During any device provisioning, whether it be manual or touch-free, by an OEM, supply factory, or end user, the provisioning process is initiated from *the device*. Either a human operator or automated provisioning system (ie, PXE boot) first bootstraps the device, then performs device registration with the enterprise or service provider network. The process described in this workflow clearly states that it's the *Verifier's* job to contact the Attestor to initiate the *provisioning* -

    "Diagram 1 depictures the steps how a new TPM device is provisioned when it is installed in a system."

Personally, I can't think of many valid use cases, if any, where the *Verifier* would initiate a *provisioning* process. It makes plenty of sense *AFTER* the device has been provisioned, either in response to a timer or network request, but not before. In addition, this also means the Verifier would need to have some way of having a "pre-registered" record of the device, including connection information, credentials, etc. It also implies the device is in some kind of pre-registered state, allowing it to at least establish a communication channel with the Verifier to complete the process, creating a chicken and egg problem.

### What's the alternative?

The Trusted Platform includes an [ACME](https://datatracker.ietf.org/doc/html/rfc8555) client and server along with support for RFC compliant (http-01, dns-01) and custom challenge types to facilitate EK certificate issuance, device enrollment and TLS certificates.

See the [docs](/docs/CA-ACME.md) for implementation details.
