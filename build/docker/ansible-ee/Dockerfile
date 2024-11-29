FROM quay.io/ansible/ansible-runner:latest

# Install required packages
RUN dnf update -y && \
    dnf install -y gcc libffi-devel python3-devel openssl-devel && \
    dnf clean all

# Set default working directory
WORKDIR /runner

# Entrypoint for Ansible Execution Environment
ENTRYPOINT ["/usr/bin/ansible-runner"]
