# JumpKit

SSH Jump Chain Analyzer

## Status

**Deprecated / Incomplete.** This project is archived and no longer maintained.

## What it does

JumpKit analyzes SSH jump chains: given a JSON config of sequential hosts (bastion → internal → target), it resolves DNS through each hop and generates the correct `ssh -J` proxy-jump command.

## Risks & limitations

- **DNS leak**: the first hop may resolve hostnames of all downstream internal-DNS hops, exposing the entire chain topology to the entry node. This is acceptable within a single cluster but a privacy concern across multiple clusters.
- Immature codebase — limited error handling, no SSH agent integration, askpass-based password auth is fragile.
- No test coverage for the analyzer or executor packages.
- Windows support is untested scaffolding.

## Config format

```json
{
  "hops": [
    {"host": "bastion.example.com", "port": 22, "user": "alice", "auth_type": "private-key"},
    {"host": "internal.db", "port": 3306, "user": "root", "auth_type": "passwd", "use_internal_dns": true}
  ]
}
```

## Usage

```bash
# TUI mode
go run ./cmd/jumpkit

# CLI mode
go run ./cmd/jumpkit -c config.json

# CLI with interactive connect
go run ./cmd/jumpkit -c config.json -x

# CLI with tunnel (SOCKS proxy on local port 1080)
go run ./cmd/jumpkit -c config.json -p 1080
```

## License

MIT
