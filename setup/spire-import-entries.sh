#!/usr/bin/env bash

echo "Importing entries into the spire-server"

podman exec spire-server /opt/spire/bin/spire-server \
    entry create -data /opt/spire/conf/server/entries.json
