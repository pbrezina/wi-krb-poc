#!/usr/bin/env bash

echo "Initializing IPA"

# PKINIT with SVID currently can not be achieved with service account
# because the certmaprule would not find it

echo "Secret123" | podman exec -i ipa kinit admin
podman exec ipa ipa user-add mcp --first="mcp-server" --last "mcp-server"
podman exec ipa ipa user-add my-user --first="my-user" --last "my-user"

Create certificate mapping (note: service principal is not supported)
podman exec ipa ipa certmaprule-add "SPIFFE" \
    --matchrule='<SAN:uniformResourceIdentifier>.*' \
    --maprule='(krbprincipalname=mcp@EXAMPLE.ORG)'
