APPNAME   ?= trusted-platform
PLATFORMD ?= platformd
VOLUME    ?= ./trusted-data

default: clean volume binaries build-debian build-alpine

.PHONY: volume
volume:
	mkdir -p $(VOLUME)/etc $(VOLUME)/log $(VOLUME)/data

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

.PHONY: clean
clean:
	rm -rf $(VOLUME) $(PLATFORMD) $(PLATFORMD)-debug
