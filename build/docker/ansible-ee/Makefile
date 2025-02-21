IMAGE_NAME=ansible-ee

default: ansible-builder load

load:
	cd context && \
		docker build --load -t $(IMAGE_NAME) .

push:
	cd context && \
		docker build --push -t jeremyhahn/$(IMAGE_NAME) .

create:
	ansible-builder create

ansible-builder:
	export DOCKER_BUILDKIT=0 && \
		ansible-builder build --tag $(IMAGE_NAME) --container-runtime=docker --verbosity 3

clean:
	-docker image rm $(IMAGE_NAME)
	-rm -rf context
