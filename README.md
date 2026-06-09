# Kerberos based workload identity PoC

## Kerberos TGT -> S4U tickets -> SSH

The PoC is functional, however there are several workarounds applied. Multiple
components must be patched in order to make the flow production ready.

```bash
# First time start up (will load rules into spire-server and setup IPA server)
make first-time-up

# Stop containers (keep data)
make stop

# Start the containers again
make up

# Check MCP logs
docker-compose logs mcp

# Remove the containers, volumes and data
make down
```
