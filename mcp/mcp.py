#!/usr/bin/env python3

import os
import textwrap
import time
from pathlib import Path

import gssapi
import krb5
import paramiko
from cryptography.hazmat.primitives import serialization
import cryptography.x509
from spiffe import WorkloadApiClient
import ipalib.x509_attestation


def fetch_svid():
    """
    Get SVID from SPIFFE.
    """
    print(f"=== Connecting to SPIFFE Workload API ===")
    with WorkloadApiClient() as client:
        svid = client.fetch_x509_svid()

        cert = svid.leaf
        print(f"Certificate Details:")
        print(f"SPIFFE ID: {svid.spiffe_id}")
        print(f"Subject: {cert.subject}")
        print(f"Issuer: {cert.issuer}")
        print(f"Serial Number: {cert.serial_number}")
        print(f"Version: {cert.version}")
        print(f"Not Before: {cert.not_valid_before_utc}")
        print(f"Not After: {cert.not_valid_after_utc}")

        # Extract SPIFFE ID from SAN
        try:
            san = cert.extensions.get_extension_for_class(
                cryptography.x509.SubjectAlternativeName
            )
            for name in san.value:
                if isinstance(name, cryptography.x509.UniformResourceIdentifier):
                    if name.value.startswith("spiffe://"):
                        print(f"SPIFFE ID from SAN: {name.value}")
        except Exception as e:
            print(f"Could not extract SPIFFE ID from SAN: {e}")

        return svid


def store_svid_to_disk(svid):
    """
    Store workload certificate and SPIRE CA chain to files.
    """
    cert_dir = Path("/certs/tmp")
    cert_file = cert_dir / "mcp.crt"
    key_file = cert_dir / "mcp.key"
    ca_bundle_file = cert_dir / "ca-bundle.crt"

    # Write certificate of the MCP server
    with open(cert_file, "wb") as f:
        f.write(svid.leaf.public_bytes(serialization.Encoding.PEM))

    # Write private key of the MCP server
    with open(key_file, "wb") as f:
        f.write(
            svid.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write full CA bundle (intermediate certificates + trust bundle root CAs)
    with open(ca_bundle_file, "wb") as f:
        # Already ordered. Exclude the leaf (MCP server cert)
        for cert in svid.cert_chain[1:]:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Store ROOT-CA
        with open("/certs/spire-root-ca.crt", "rb") as root_ca:
            f.write(root_ca.read())

        # Store IPA CA
        with open("/ipa-data/etc/ipa/ca.crt", "rb") as ipa_ca:
            f.write(ipa_ca.read())

    print(f"=== SVID stored to disk ===")
    print(f"Certificate: {cert_file}")
    print(f"Private Key: {key_file}")
    print(f"CA Bundle: {ca_bundle_file}")

    return cert_file, key_file


def acquire_tgt_with_pkinit(principal_name, cert_path, key_path, ccache_path):
    """
    This currently requires regular IPA user (ipa user-add) instead of a service
    principal (ipa service-add), because IPA does not support certificate
    mapping to a service account.

    However, regular user does not support ok-to-auth-as-delegate to get S4U
    tickets, this is only supported in a service account.

    Therefore PKINIT with SVID is not yet fully supported.
    """
    print(f"=== Acquiring TGT with PKINIT ===")

    ctx = krb5.init_context()

    # Resolve principal
    principal = krb5.parse_name_flags(ctx, principal_name.encode())

    # Get TGT with PKINIT
    identity = f"FILE:{cert_path},{key_path}".encode()
    options = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_pa(ctx, options, b"X509_user_identity", identity)

    creds = krb5.get_init_creds_password(ctx, principal, options, password=None)

    print(f"Successfully acquired TGT for {principal_name}")

    # Store it in ccache
    cc = krb5.cc_resolve(ctx, ccache_path.encode())
    krb5.cc_initialize(ctx, cc, principal)
    krb5.cc_store_cred(ctx, cc, creds)

    print(f"TGT successfully written to cache: {ccache_path}")


def acquire_tgt_with_keytab(principal_name, keytab_path, ccache_path):
    """
    Acquire TGT using a keytab with GSSAPI.

    Args:
        principal_name: Kerberos principal (e.g., 'mcp@EXAMPLE.ORG')
        keytab_path: Path to the keytab file
        ccache_path: Path to credential cache (e.g., 'MEMORY:ccache')
    """
    print(f"=== Acquiring TGT with keytab ===")

    # Set environment variables for GSSAPI
    os.environ["KRB5_CLIENT_KTNAME"] = keytab_path
    os.environ["KRB5CCNAME"] = ccache_path

    # Parse principal name
    name = gssapi.Name(principal_name, gssapi.NameType.kerberos_principal)

    # Acquire credentials using keytab
    # This will obtain a TGT from the KDC and store it in the ccache
    creds = gssapi.Credentials(name=name, usage="initiate")

    print(f"Successfully acquired TGT for {principal_name}")
    print(f"Credential lifetime: {creds.lifetime} seconds")
    print(f"TGT successfully written to cache: {ccache_path}")

    return creds


def acquire_s4u_ticket(mcp_principal, user_principal, host_principal, s4u_ccache):
    print(f"=== Acquiring S4U2Self ticket for user {user_principal} ===")

    service_name = gssapi.Name(mcp_principal, gssapi.NameType.kerberos_principal)
    user_name = gssapi.Name(user_principal, gssapi.NameType.kerberos_principal)

    # Get our service credentials (already acquired with keytab)
    service_creds = gssapi.Credentials(name=service_name, usage="initiate")
    print(f"Service credentials acquired for: {service_name}")

    # S4U2Self: Acquire a ticket for the user to our service
    user_creds = service_creds.impersonate(user_name)
    user_creds.store({"ccache": s4u_ccache}, overwrite=True)
    os.environ["KRB5CCNAME"] = s4u_ccache

    print(f"Successfully acquired S4U2Self ticket for {user_principal}")
    print(f"S4U2Self credential lifetime: {user_creds.lifetime} seconds")
    print(f"S4U2Self ticket successfully written to cache: {s4u_ccache}")

    # S4U2Proxy: Use the user's credentials to access the target service
    #
    # This step is currently skipped as it is done later by GSSAPI in Paramiko.
    #
    # host_name = gssapi.Name(host_principal, gssapi.NameType.kerberos_principal)
    # ctx = gssapi.SecurityContext(
    #     name=host_name,
    #     creds=user_creds,
    #     usage='initiate'
    # )
    #
    # Complete the context establishment
    # ctx.step()
    #
    # print(f"Successfully acquired S4U2Proxy ticket for {host_principal}")
    # print(f"Security context established for {user_principal} -> {host_principal}")


def ipa_build_attestation_cert(
    svc_hostname,
    svc_pubkey_path,
    svc_keytab_path,
    realm,
    user,
    original_user,
    request_id,
    *,
    agent_name=None,
    agent_model=None,
    tool_id=None,
    oauth2_token=None,
):
    print(f"=== Building S4U attestation certificate ===")

    keytab_entry = ipalib.x509_attestation.get_host_keytab_key(
        hostname=svc_hostname,
        service_type="mcp",
        keytab_path=svc_keytab_path,
        realm=realm,
    )

    with open(svc_pubkey_path, "rb") as f:
        cert = cryptography.x509.load_pem_x509_certificate(f.read())
        pubkey = cert.public_key()

    cert_der = ipalib.x509_attestation.build_mcp_attestation_cert(
        user=user,
        realm=realm,
        original_user=original_user,
        request_id=request_id,
        host_pubkey=pubkey,
        keytab_entry=keytab_entry,
        agent_name=agent_name,
        agent_model=agent_model,
        tool_id=tool_id,
        oauth2_token=oauth2_token,
    )

    return cert_der


def print_attestation_cert_info(cert_der):
    """Parse and print information from an MCP attestation certificate."""
    cert = cryptography.x509.load_der_x509_certificate(cert_der)

    print(f"  Subject: {cert.subject.rfc4514_string()}")
    print(f"  Issuer: {cert.issuer.rfc4514_string()}")
    print(f"  Not Before: {cert.not_valid_before_utc}")
    print(f"  Not After: {cert.not_valid_after_utc}")

    # Parse McpAuthnContext extension (OID 2.16.840.1.113730.3.8.15.3.4)
    OID_MCP_AUTHN_CONTEXT = "2.16.840.1.113730.3.8.15.3.4"
    try:
        ext = cert.extensions.get_extension_for_oid(
            cryptography.x509.ObjectIdentifier(OID_MCP_AUTHN_CONTEXT)
        )
        fields = _parse_mcp_authn_context(ext.value.value)
        print(f"  MCP Authn Context:")
        print(f"    Original User: {fields.get('original_user', 'N/A')}")
        print(f"    Request ID: {fields.get('request_id', 'N/A')}")
        if fields.get("agent_name"):
            print(f"    Agent Name: {fields['agent_name']}")
        if fields.get("agent_model"):
            print(f"    Agent Model: {fields['agent_model']}")
        if fields.get("tool_id"):
            print(f"    Tool ID: {fields['tool_id']}")
        if fields.get("oauth2_token"):
            print(f"    OAuth2 Token: {fields['oauth2_token']}")
    except cryptography.x509.ExtensionNotFound:
        print(f"  MCP Authn Context: not present")


def _parse_mcp_authn_context(der_bytes):
    """
    Parse the DER-encoded McpAuthnContext SEQUENCE:
      SEQUENCE {
        version       INTEGER (0),
        originalUser  UTF8String,
        requestId     UTF8String,
        agentName     [0] EXPLICIT UTF8String OPTIONAL,
        agentModel    [1] EXPLICIT UTF8String OPTIONAL,
        toolId        [2] EXPLICIT UTF8String OPTIONAL,
        oauth2Token   [3] EXPLICIT UTF8String OPTIONAL
      }
    """
    result = {}
    data = memoryview(der_bytes)

    def read_tlv(buf):
        tag = buf[0]
        if buf[1] & 0x80:
            n_len_bytes = buf[1] & 0x7F
            length = int.from_bytes(buf[2:2 + n_len_bytes], "big")
            header = 2 + n_len_bytes
        else:
            length = buf[1]
            header = 2
        value = bytes(buf[header:header + length])
        rest = buf[header + length:]
        return tag, value, rest

    # Outer SEQUENCE
    tag, seq_body, _ = read_tlv(data)
    data = memoryview(seq_body)

    # version (INTEGER, tag 0x02) - skip
    tag, _, data = read_tlv(data)

    # originalUser (UTF8String, tag 0x0C)
    tag, val, data = read_tlv(data)
    result["original_user"] = val.decode()

    # requestId (UTF8String, tag 0x0C)
    tag, val, data = read_tlv(data)
    result["request_id"] = val.decode()

    # Optional context-tagged fields [0]-[3]
    tag_map = {0xA0: "agent_name", 0xA1: "agent_model",
               0xA2: "tool_id", 0xA3: "oauth2_token"}
    while len(data) > 0:
        tag, val, data = read_tlv(data)
        if tag in tag_map:
            # EXPLICIT: inner TLV is a UTF8String
            _, inner_val, _ = read_tlv(memoryview(val))
            result[tag_map[tag]] = inner_val.decode()

    return result


def ipa_acquire_s4u2self_ticket(mcp_principal, cert, s4u_ccache):
    # GSS_KRB5_NT_X509_CERT: 1.2.840.113554.1.2.2.7
    # Imports raw X.509 cert DER as a Kerberos principal name for PA-FOR-X509-USER.
    GSS_KRB5_NT_X509_CERT = gssapi.OID.from_int_seq([1, 2, 840, 113554, 1, 2, 2, 7])

    print(f"=== Acquiring S4U2Self ticket with IPA attestation cert ===")
    print_attestation_cert_info(cert)

    service_name = gssapi.Name(mcp_principal, gssapi.NameType.kerberos_principal)
    cert_name = gssapi.Name(cert, name_type=GSS_KRB5_NT_X509_CERT)

    # Get our service credentials (already acquired with keytab)
    service_creds = gssapi.Credentials(name=service_name, usage="initiate")
    print(f"Service credentials acquired for: {service_name}")

    # S4U2Self: Acquire a ticket for the user to our service
    user_creds = service_creds.impersonate(cert_name)
    user_creds.store({"ccache": s4u_ccache}, overwrite=True)
    os.environ["KRB5CCNAME"] = s4u_ccache

    user_principal = str(user_creds.name)

    print(f"Successfully acquired S4U2Self ticket for {user_principal}")
    print(f"S4U2Self credential lifetime: {user_creds.lifetime} seconds")
    print(f"S4U2Self ticket successfully written to cache: {s4u_ccache}")

    return user_principal


def paramiko_exec(ssh, command):
    """
    Execute command over ssh.
    """

    print(f"Executing: {command}")

    _, stdout, stderr = ssh.exec_command(command)

    exit_status = stdout.channel.recv_exit_status()
    stdout_data = stdout.read().decode("utf-8")
    stderr_data = stderr.read().decode("utf-8")

    print(textwrap.indent(f"Exit status: {exit_status}", "    "))
    if stdout_data:
        print(textwrap.indent("STDOUT:", "    "))
        print(textwrap.indent(stdout_data, "    "))

    if stderr_data:
        print(textwrap.indent("STDERR:", "    "))
        print(textwrap.indent(stderr_data, "    "))


def paramiko_run(hostname, user):
    """
    Connect to SSH server using GSSAPI authentication with S4U2Proxy ticket.
    """
    print(f"=== Connecting to SSH server {hostname} ===")

    # Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname=hostname, username=user, gss_auth=True)

        print(f"Successfully connected to {hostname} as {user} via SSH with GSSAPI")

        # Show identity used to login
        paramiko_exec(ssh, "whoami")

        # Show who we are
        paramiko_exec(ssh, "id")

        # Show that we have kerberos tickets
        paramiko_exec(ssh, "klist")

        # And we can run authenticated sudo command
        paramiko_exec(ssh, "sudo ls /root")

        # And we can run authenticated IPA command
        paramiko_exec(ssh, "ipa user-find")

        # Make sure we don't leave any ticket behind to taint next attempts
        paramiko_exec(ssh, "kdestroy -A")
    finally:
        ssh.close()
        print(f"SSH connection closed")


def podman_wait():
    """
    Wait for ten seconds and flush the logs so podman can see them.
    """
    print(f"Sleeping for 10 seconds...")
    print("", flush=True)
    time.sleep(10)


def run_cycle():
    try:
        svid = fetch_svid()
    except Exception as e:
        print(f"Error fetching SPIFFE identity: {e}")
        return

    # Store SVID to disk for kinit PKINIT
    cert_file, key_file = store_svid_to_disk(svid)

    try:
        # Perform PKINIT authentication
        # Currently not possible with service principal.
        # try:
        #     acquire_tgt_with_pkinit('mcp@EXAMPLE.ORG', cert_file, key_file, "MEMORY:ccache")
        # except Exception as auth_error:
        #     print(f"PKINIT authentication failed: {auth_error}")
        acquire_tgt_with_keytab(
            "mcp/mcp.example.org@EXAMPLE.ORG",
            "/certs/tmp/mcp.keytab",
            "MEMORY:ccache",
        )
    except Exception as e:
        print(f"Could not get TGT: {e}")
        return

    try:
        # acquire_s4u_ticket(
        #     "mcp/mcp.example.org@EXAMPLE.ORG",
        #     "admin@EXAMPLE.ORG",
        #     "host/staging.example.org@EXAMPLE.ORG",
        #     "MEMORY:s4u2proxy",
        # )
        cert = ipa_build_attestation_cert(
            svc_hostname="mcp.example.org",
            svc_pubkey_path="/certs/mcp.crt",
            svc_keytab_path="/certs/tmp/mcp.keytab",
            realm="EXAMPLE.ORG",
            user="admin",
            original_user="admin",
            request_id="0c2b44f8-98f9-4bab-ad07-412bf26a63ed",
            agent_name="claude",
            agent_model="opus",
            tool_id="rhel-mcp",
            oauth2_token="poc-dummy-token",
        )

        user = ipa_acquire_s4u2self_ticket(
            "mcp/mcp.example.org@EXAMPLE.ORG", cert, "MEMORY:s4u2proxy"
        )

    except Exception as e:
        print(f"Error getting S4U tickets: {e}")
        return

    try:
        paramiko_run("staging.example.org", user)
    except Exception as e:
        print(f"SSH Connection Failed: {e}")
        return


def main():
    run_cycle()

    while True:
        podman_wait()


if __name__ == "__main__":
    main()
