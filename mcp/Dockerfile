FROM fedora:latest

# Install dependencies
RUN dnf install -y python3 python3-pip gcc python3-devel \
        krb5-workstation krb5-devel openssl openssh-clients && \
    dnf clean all

# Install IPA lib
RUN dnf copr enable -y pbrezina/s4u && \
    dnf install -y python3-ipalib && \
    dnf clean all

# Create virtual environment
RUN python3 -m venv --system-site-packages /opt/venv

# Install Python dependencies; paramiko-5 removed gssapi support
RUN /opt/venv/bin/pip3 install --no-cache-dir spiffe gssapi krb5 "paramiko<5.0.0"

# Copy Kerberos configuration
COPY krb5.conf /etc/krb5.conf

# Set the working directory
WORKDIR /mcp

# Use the virtual environment by default
ENV PATH="/opt/venv/bin:$PATH"

# Set the entrypoint
ENTRYPOINT ["/mcp/mcp.py"]
