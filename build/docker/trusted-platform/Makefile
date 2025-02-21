APPNAME   ?= trusted-platform
CONFIG    ?= ../../../configs/platform/local/server/config.yaml
PLATFORMD ?= platformd
VOLUME    ?= ./trusted-data

default: clean volume config binaries build-debian build-alpine

.PHONY: volume
volume:
	mkdir -p $(VOLUME)/etc $(VOLUME)/log $(VOLUME)/data

.PHONY: config
config:
	CONTAINER=$$(docker create $(APPNAME)-builder-alpine:amd64); \
	docker cp $$CONTAINER:/builder/go-trusted-platform/configs/platform/config.dev.server.yaml $(VOLUME)/etc/config.yaml

.PHONY: binaries
binaries:
	# x86_64
	CONTAINER=$$(docker create $(APPNAME)-builder-alpine:amd64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-static $(PLATFORMD); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug-static $(PLATFORMD)-debug
	# ARM64
	CONTAINER=$$(docker create $(APPNAME)-builder-alpine:arm64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-static $(PLATFORMD); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug-static $(PLATFORMD)-debug

.PHONY: build-debian
build-debian:
	docker build --load \
		--platform=linux/amd64 \
		--build-arg PLATFORMD=$(PLATFORMD) \
		-t $(APPNAME)-debian:amd64 \
		-f Dockerfile-debian .
	docker build --load \
		--platform=linux/arm64 \
		--build-arg PLATFORMD=$(PLATFORMD) \
		-t $(APPNAME)-debian:arm64 \
		-f Dockerfile-debian .

.PHONY: build-alpine
build-alpine:
	docker build --load \
		--platform=linux/amd64 \
		--build-arg PLATFORMD=$(PLATFORMD) \
		-t $(APPNAME)-alpine:amd64 \
		-f Dockerfile-alpine .
	docker build --load \
		--platform=linux/arm64 \
		--build-arg PLATFORMD=$(PLATFORMD) \
		-t $(APPNAME)-alpine:arm64 \
		-f Dockerfile-alpine .

.PHONY: run-debian
run-debian: volume config
	docker run -it --rm \
		-v $(VOLUME):/trusted-platform \
		$(APPNAME)-debian:amd64 \
			webservice \
				--debug \
				--init \
				--config-dir /trusted-platform/etc \
				--log-dir /trusted-platform/log \
				--platform-dir /trusted-platform/data \
				--ca-dir /trusted-platform/data/ca \
				--raw-so-pin 123456 \
				--raw-pin 123456

.PHONY: run-alpine
run-alpine: volume config
	docker run -it --rm \
		-v $(VOLUME):/trusted-platform \
		$(APPNAME)-alpine:amd64 \
			webservice \
				--debug \
				--init \
				--config-dir /trusted-platform/etc \
				--log-dir /trusted-platform/log \
				--platform-dir /trusted-platform/data \
				--ca-dir /trusted-platform/data/ca \
				--raw-so-pin 123456 \
				--raw-pin 123456

.PHONY: published-server
published-server:
	@echo "Starting published Platform as a Service with config: $(CONFIG)"
	mkdir -p server/etc server/log server/data
	cp ../../../configs/platform/local/server/config.yaml etc/config.yaml
	@docker run -it --rm \
		-v $(PWD)/server/etc:/trusted-platform/etc \
		-v $(PWD)/server/log:/trusted-platform/log \
		-v $(PWD)/server/data:/trusted-platform/data \
		jeremyhahn/trusted-platform:latest \
			webservice \
			--debug \
			--init \
			--config-dir /trusted-platform/etc \
			--log-dir /trusted-platform/log \
			--platform-dir /trusted-platform/data \
			--ca-dir /trusted-platform/data/ca \
			--raw-so-pin 123456 \
			--raw-pin 123456

.PHONY: published-client
published-client:
	@echo "Starting Platform using published client with config: $(CONFIG)"
	mkdir -p etc log data
	cp ../../../configs/platform/local/client/config.yaml etc/config.yaml
	@docker run -it --rm \
		-v $(PWD)/server/etc:/trusted-platform/etc \
		-v $(PWD)/server/log:/trusted-platform/log \
		-v $(PWD)/server/data:/trusted-platform/data \
		jeremyhahn/trusted-platform:latest \
			webservice \
			--debug \
			--init \
			--config-dir /trusted-platform/etc \
			--log-dir /trusted-platform/log \
			--platform-dir /trusted-platform/data \
			--ca-dir /trusted-platform/data/ca \
			--raw-so-pin 123456 \
			--raw-pin 123456

.PHONY: clean
clean:
	rm -rf $(VOLUME) $(PLATFORMD) $(PLATFORMD)-debug
