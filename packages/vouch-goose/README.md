# vouch-goose

Make Block's [Goose](https://github.com/block/goose) agent Vouch-aware. Goose
runs its tools from MCP servers registered as extensions, and Vouch ships an MCP
server (`vouch-mcp`), so this package registers that server as a Goose extension.
Then any Goose session can create an identity, sign and verify credentials, scan
for leaked keys, and decode DIDs.

## Install

```bash
pip install vouch-goose      # pulls vouch-mcp
```

## One command to wire it in

```bash
vouch-goose
```

This adds a `vouch` extension to `~/.config/goose/config.yaml`, creating the file
if needed and leaving your other extensions untouched. Start Goose and the Vouch
tools are available.

Options:

```bash
vouch-goose --config /path/to/config.yaml   # a non-default Goose config
vouch-goose --name my-vouch                 # a different extension name
vouch-goose --keep-existing                 # do not overwrite an existing entry
```

## Or wire it in from Python

```python
from vouch.integrations.goose import install, extension_config

install()                 # writes the extension into the Goose config
extension_config()        # the config entry, if you would rather merge it yourself
```

## What it writes

```yaml
extensions:
  vouch:
    enabled: true
    type: stdio
    cmd: vouch-mcp
    args: []
    timeout: 300
```

## License

Apache-2.0. Part of the [Vouch Protocol](https://github.com/vouch-protocol/vouch).
