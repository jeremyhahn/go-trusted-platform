APPBIN             ?= verifier

VERIFIER_DIR       ?= ./
PLATFORM_DIR       ?= trusted-data
CONFIG_DIR         ?= $(PLATFORM_DIR)/etc
LOG_DIR            ?= $(PLATFORM_DIR)/log
CA_DIR             ?= $(PLATFORM_DIR)/ca
ATTESTATION_CONFIG ?= attestation.yaml

VERIFIER_CA        ?= $(PLATFORM_DIR)/ca
VERIFIER_CONF      ?= $(CONFIG_DIR)/config.yaml
VERIFIER_DOMAIN    ?= verifier.local
VERIFIER_HOSTNAME  ?= www

ATTESTOR_HOSTNAME  ?= www
ATTESTOR_DOMAIN    ?= attestor.local

CONFIG_YAML_SRC    ?= config.yaml

CONFIG_DIR_DST     ?= $(PLATFORM_DIR)/etc
CONFIG_YAML_DST    ?= $(CONFIG_DIR_DST)/config.yaml

ROOT_CA            ?= root-ca
INTERMEDIATE_CA    ?= intermediate-ca
DOMAIN             ?= verifier.local

PLATFORM_CONFIG_DIR ?= ../../../configs

PROTOC             ?= protoc
PROTO_DIR		   ?= pkg/proto

.PHONY: env build clean config verifier-init verifier verifier-no-clean verifier-cert-chain


default: clean proto build verifier-init


env:
	@echo "VERIFIER_DIR: \t\t$(VERIFIER_DIR)"
	@echo "PLATFORM_DIR: \t\t$(PLATFORM_DIR)"
	@echo "CONFIG_DIR: \t\t$(CONFIG_DIR)"
	@echo "LOG_DIR: \t\t$(LOG_DIR)"
	@echo "CA_DIR: \t\t$(CA_DIR)"
	@echo "DOMAIN: \t\t$(DOMAIN)"
	@echo "ATTESTOR_HOSTNAME: \t$(ATTESTOR_HOSTNAME)"
	@echo "VERIFIER_HOSTNAME: \t$(VERIFIER_HOSTNAME)"
	@echo "CONFIG_YAML_SRC: \t$(CONFIG_YAML_SRC)"
	@echo "VERIFIER_CONF: \t\t$(VERIFIER_CONF)"
	@echo "VERIFIER_CA: \t\t$(VERIFIER_CA)"
	@echo "ROOT_CA: \t\t$(ROOT_CA)"
	@echo "INTERMEDIATE_CA: \t$(INTERMEDIATE_CA)"


deps:
	sudo apt-get -y update
	go install -v golang.org/x/tools/gopls@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
	sudo apt-get install -y protobuf-compiler protoc-gen-go protoc-gen-go-grpc


build:
	cd pkg && go build -o ../$(APPBIN)


clean:
	rm -rf $(APPBIN) \
		$(PLATFORM_DIR) \
		pkg/$(PLATFORM_DIR) \
		$(PROTO_DIR)/*.pb.go


config:
	mkdir -p $(PLATFORM_DIR)/etc
	cp $(CONFIG_YAML_SRC) $(CONFIG_YAML_DST)


proto:
	cd $(PROTO_DIR) && $(PROTOC) \
		--go_out=. \
		--go_opt=paths=source_relative \
    	--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		attestation.proto


verifier-init:
	./$(APPBIN) \
		-init=true \
		-attestor www.attestor.local \
		-so-pin 123456 \
		-pin 123456


verifier:
	./$(APPBIN) \
		-attestor www.attestor.local \
		-so-pin 123456 \
		-pin 123456


verifier-no-clean: build
	./$(APPBIN) \
		-attestor www.attestor.local \
		-so-pin 123456 \
		-pin 123456


verifier-cert-chain:
	@openssl x509 \
		-inform der \
		-in $(VERIFIER_CA)/$(ROOT_CA).$(DOMAIN)/x509/$(ROOT_CA).$(DOMAIN).pkcs8.rsa.cer \
		-out $(VERIFIER_CA)/$(ROOT_CA).$(DOMAIN)/x509/$(ROOT_CA).$(DOMAIN).pkcs8.rsa.pem
	@openssl x509 \
		-inform der \
		-in $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(INTERMEDIATE_CA).$(DOMAIN).pkcs8.rsa.cer \
		-out $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(INTERMEDIATE_CA).$(DOMAIN).pkcs8.rsa.pem
	@openssl x509 \
		-inform der \
		-in $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(VERIFIER_HOSTNAME).$(DOMAIN).pkcs8.rsa.cer \
		-out $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(VERIFIER_HOSTNAME).$(DOMAIN).pkcs8.rsa.pem
	openssl verify \
		-CAfile $(VERIFIER_CA)/$(ROOT_CA).$(DOMAIN)/x509/$(ROOT_CA).$(DOMAIN).pkcs8.rsa.pem \
		-untrusted $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(INTERMEDIATE_CA).$(DOMAIN).pkcs8.rsa.pem \
		$(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(VERIFIER_HOSTNAME).$(DOMAIN).pkcs8.rsa.pem
