#!/usr/bin/env bash

# Fetch keytab for mcp service principal so it can be used in mcp.py
podman exec ipa ipa-getkeytab -s ipa.example.org -p mcp/mcp.example.org -k /certs/tmp/mcp.keytab
