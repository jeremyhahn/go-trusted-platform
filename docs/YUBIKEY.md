# YubiKey

This document provides helpful information on YubiKey features, limits, and how it's used within the Trusted Platform.


# Default Credentials

* PIN: "123456"
* PUK: "12345678"
* Management Key: (Firmware Version 5.6 and below: Triple-DES / 5.7 and above: AES-192), 0x010203040506070801020304050607080102030405060708
0102030405060708 three times


# PIV Slots

| Slot # | Name                | Since             | Description                    |
| ------ | ----                | -----             | -----------                    |
| 80     | PIN                 | 5.3               | Personal Identification Number | 
| 81     | PUK                 | 5.3               | Pin unblocking key             |
| 9B     | Management          | all               | Management key                 |
| 9A     | PIV Authentication  | all               | RSA or ECC key and cert, authenticate the user, usually for system login |
| 9C     | Digital Signature   | all               | RSA or ECC key and cert, signing email, files, executables, etc. |
| 9D     | Key Management      | all               | RSA or ECC key and cert, encryption for confidentiality, e.g. decrypting email |
| 9E     | Card Authentication | all               | RSA or ECC key and cert, authenticate the card, usually building access |
| F9     | Attestation         | 4.3               | Attests a key in slot 9A, 9C, 9D, or 9E was generated on the YubiKey |
| 82     | Retired 1           | 4.0               | RSA or ECC key and cert, usually keys with expired certs, used to decrypt older emails or other encrypted items |
| 83     | Retired 2           | 4.0               | RSA or ECC key and cert, usually keys with expired certs, used to decrypt older emails or other encrypted items |
| 84-94  | ...                 | ...               | Stores arbitrary asymmetric keys |
| 95     | Retired 20          | 4.0               | RSA or ECC key and cert, usually keys with expired certs, used to decrypt older emails or other encrypted items |


# PKCS #11 Key Mappings

| ykcs11 id | PIV   |
| --------- | ----- |
| 1         | 9a    |
| 2         | 9c    |
| 3         | 9d    |
| 4         | 9c    |
| 5-24      | 82-95 |
| 25        | f9    |


https://developers.yubico.com/yubico-piv-tool/YKCS11/

https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html


# OTP Server

Here you can generate a shared symmetric key for use with the Yubico Web Services. You need to authenticate yourself using a Yubico One-Time Password and provide your e-mail address as a reference.

https://upgrade.yubico.com/getapikey/

After entering your email address and YubiKey OTP, you should receive client ID
and secret key in your inbox. This client ID is used by the Trusted Platform to
validate the OTP codes for your key.

The detailed walk-through is here:

https://developers.yubico.com/OTP/OTP_Walk-Through.html


##### Single Factor OTP Test

https://demo.yubico.com/otp/verify

##### Second Factor OTP Test

https://demo.yubico.com/playground



# Limits

[How many accounts can I register my YubiKey with](https://support.yubico.com/hc/en-us/articles/360013790319-How-many-accounts-can-I-register-my-YubiKey-with)
