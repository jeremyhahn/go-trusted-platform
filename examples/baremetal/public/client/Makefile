# This Makefile provides examples to generate the platform software
# configuration file, initialize the platform, and run the embedded
# TLS enabled web services using a cross-signed certificate from a
# public ACME server, such as Let's Encrypt. This Makefile launches
# the platform software in server mode, which includes additional
# components such as the ACME and DNS services which allow "joining"
# clients to the trusted network.

# The DOMAIN must be publicly routable and accessible for the ACME
# cross-signer to verify domain ownership. If the domain is not
# publicly accessible, set CROSS_SIGNER to an empty string.
#
# Example: CROSS_SIGNER= DOMAIN=dev.trusted-platform.io make

# This example uses Let's Encrypt, but any RFC-8555 compliant ACME
# server can be used to cross-sign the certificate. 

# Let's Encrypt Prod:    https://acme-v02.api.letsencrypt.org/directory
# Let's Encrypt Staging: https://acme-staging-v02.api.letsencrypt.org/directory


APPBIN             ?= platformd
PLATFORM_DIR       ?= trusted-data
CONFIG_DIR         ?= $(PLATFORM_DIR)/etc
LOG_DIR            ?= $(PLATFORM_DIR)/log
CA_DIR             ?= $(PLATFORM_DIR)/ca
PASSWORD		   ?= example
DOMAIN             ?= example.com
SERVER_DIRECTORY   ?= https://dev.trusted-platform.io/api/v1/acme/directory
CROSS_SIGNER       ?= https://acme-staging-v02.api.letsencrypt.org/directory

default: clean build config-nonfips run

.PHONY: env
env:
	@echo "APPBIN: \t\t$(APPBIN)"
	@echo "PLATFORM_DIR: \t\t$(PLATFORM_DIR)"
	@echo "CONFIG_DIR: \t\t$(CONFIG_DIR)"
	@echo "LOG_DIR: \t\t$(LOG_DIR)"
	@echo "CA_DIR: \t\t$(CA_DIR)"
	@echo "PASSWORD: \t$(PASSWORD)"
	@echo "DOMAIN: \t$(DOMAIN)"
	@echo "CROSS_SIGNER: \t$(CROSS_SIGNER)"

.PHONY: build
build:
	cd ../../ && make

.PHONY: clean
clean:
	rm -rf $(PLATFORM_DIR)

.PHONY: config
config:
	../../$(APPBIN) config gen \
		--type client \
		--init \
		--debug=true \
		--debug-secrets=true \
		--domain $(DOMAIN) \
		--acme-directory-url "$(SERVER_DIRECTORY)" \
		--acme-cross-signer-url "$(CROSS_SIGNER)" \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD)

.PHONY: config-nonfips
config-nonfips:
	../../$(APPBIN) config gen \
		--type client \
		--init \
		--debug=true \
		--debug-secrets=true \
		--fips=false \
		--domain $(DOMAIN) \
		--acme-directory-url "$(SERVER_DIRECTORY)" \
		--acme-cross-signer-url "$(CROSS_SIGNER)" \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD)

.PHONY: run
run:
	../../$(APPBIN) webservice
