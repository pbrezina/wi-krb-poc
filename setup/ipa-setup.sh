#!/usr/bin/env bash

set -ex

echo "Initializing IPA"

# Enroll staging.example.org to IPA
podman exec -i staging ipa-client-install \
    --server=ipa.example.org \
    --domain=example.org \
    --realm=EXAMPLE.ORG \
    --principal=admin \
    --password=Secret123 \
    --fixed-primary \
    --preserve-sssd \
    --no-ntp \
    --mkhomedir \
    --unattended \
    --force

# Copy sssd.conf to staging container to override changes by ipa-client-install
# The configuration enables gssapi auth for sudo
podman cp staging/sssd.conf staging:/etc/sssd/sssd.conf
podman exec staging chown root:sssd /etc/sssd/sssd.conf
podman exec staging chmod 640 /etc/sssd/sssd.conf
podman exec staging systemctl restart sssd

# Enable with-gssapi with authselect
podman exec staging authselect select sssd with-gssapi with-mkhomedir with-sudo --force

# kinit so we can run administrative ipa commands
echo "Secret123" | podman exec -i ipa kinit admin

# Update public key of the staging server
PUBKEY=`podman exec staging cat /etc/ssh/ssh_host_rsa_key.pub`
podman exec ipa ipa host-mod staging.example.org --sshpubkey="$PUBKEY"

# Create MCP service principal with an attestation key for S4U certificate attestation
podman exec ipa ipa host-add mcp.example.org --force
podman exec ipa ipa service-add mcp/mcp.example.org --ok-to-auth-as-delegate=true --force
podman exec ipa ipa service-add-attestation-key mcp/mcp.example.org --type="mcp" --pubkey=/certs/mcp.crt

# Setup S4U2Proxy delegation: MCP can acquire S4U2Proxy ticket to connect to the staging server
podman exec ipa ipa servicedelegationtarget-add mcp-delegation
podman exec ipa ipa servicedelegationtarget-add-member mcp-delegation --principals=host/staging.example.org
podman exec ipa ipa servicedelegationrule-add mcp-s4u2proxy-rule
podman exec ipa ipa servicedelegationrule-add-member mcp-s4u2proxy-rule --principals=mcp/mcp.example.org
podman exec ipa ipa servicedelegationrule-add-target mcp-s4u2proxy-rule --servicedelegationtargets=mcp-delegation

# SSH server on the staging server will acquire S4U2Self and S4U2Proxy for
# HTTP/ipa.example.org on behalf of the logged in user. So the user can run
# gssapi-authenticated sudo and ipa command.
podman exec ipa ipa service-add-delegation HTTP/ipa.example.org host/staging.example.org

# Add sudo rule to allow admin user run sudo
podman exec ipa ipa sudorule-add admin-all \
    --desc="Allow admin to run any command on any host" \
    --hostcat=all --cmdcat=all
podman exec ipa ipa sudorule-add-user admin-all --users=admin

podman exec ipa dsconf slapd-EXAMPLE-ORG config replace nsslapd-errorlog-level=16392