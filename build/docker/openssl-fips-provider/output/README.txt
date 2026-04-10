OpenSSL FIPS 140-3 Provider Module
===================================

FIPS Validated Version: 3.1.2
Certificate: #4985
Valid Until: March 10, 2030
Build Date: 2025-12-06 08:55:43

This package contains ONLY the FIPS provider module (fips.so).

IMPORTANT: This FIPS provider is compatible with ANY OpenSSL 3.x version.
- Built from: OpenSSL 3.1.2 (FIPS 140-3 validated)
- Compatible with: OpenSSL 3.0.x - 3.5.x+
- Use with: Alpine's system OpenSSL package (currently 3.5.4)

Installation:
  1. Install Alpine's system OpenSSL: apk add openssl
  2. Copy fips.so to: /usr/lib/ossl-modules/fips.so
  3. Run: openssl fipsinstall -out /etc/ssl/fipsmodule.cnf -module /usr/lib/ossl-modules/fips.so
  4. Configure OpenSSL to use FIPS provider in /etc/ssl/openssl.cnf

This approach:
  - Maintains FIPS compliance (validated FIPS provider from 3.1.2)
  - Ensures compatibility (uses Alpine's 3.5.4 libraries for system libraries)
  - Follows official OpenSSL documentation

References:
- https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985
- https://github.com/openssl/openssl/blob/master/README-FIPS.md
- https://openssl-library.org/post/2025-03-11-fips-140-3/
