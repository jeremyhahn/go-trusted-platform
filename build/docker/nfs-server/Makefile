
default: clean init build run mount

.PHONY: init
init:
	mkdir -p data mnt
	echo "it works!" > data/test.txt

.PHONY: build
build:
	docker buildx build --load -t nfs-server .

.PHONY: push
push:
	docker buildx build --push -t jeremyhahn/nfs-server .

.PHONY: run
run: clean
	docker run -d --name nfs-server --privileged -v $(shell pwd)/data:/exports nfs-server

.PHONY: get-ip
get-ip:
	@echo "Getting NFS server IP address..."
	@for i in {1..10}; do \
		IP=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nfs-server); \
		if [ -n "$$IP" ]; then \
			echo "NFS server IP: $$IP"; \
			echo $$IP > .nfs_server_ip; \
			break; \
		fi; \
		echo "Waiting for NFS server to get an IP..."; \
		sleep 2; \
	done

.PHONY: wait-for-nfs
wait-for-nfs:
	@echo "Waiting for NFS server to be ready..."
	@for i in {1..10}; do \
		IP=$$(cat .nfs_server_ip); \
		if showmount -e $$IP >/dev/null 2>&1; then \
			echo "NFS server is ready"; \
			break; \
		fi; \
		echo "Waiting for NFS server to be ready..."; \
		sleep 2; \
	done

.PHONY: mount
mount: get-ip wait-for-nfs
	mkdir -p mnt
	@IP=$$(cat .nfs_server_ip) && \
	echo "Mounting NFS server at $$IP:/exports to $(shell pwd)/mnt/..." && \
	sudo mount -t nfs $$IP:/exports $(shell pwd)/mnt/ && \
	echo "Mounted successfully." && \
	echo "Contents of mounted directory:" && \
	ls -l mnt/

.PHONY: clean
clean:
	-sudo umount -f mnt
	-docker rm -f nfs-server
	-rm -rf data mnt .nfs_server_ip
