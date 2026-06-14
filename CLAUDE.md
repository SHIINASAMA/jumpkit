# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Key Rules

- **Never commit or push code** unless the user explicitly asks you to commit. Do not stage files, run `git commit`, or create PRs without a direct user request.

## Build & Test

```bash
# Build (use GOPROXY=off per project settings)
GOPROXY=off go build -o jumpkit ./cmd/jumpkit

# Run all tests
GOPROXY=off go test ./...

# Run tests for a single package
GOPROXY=off go test ./pkg/resolver/
GOPROXY=off go test ./pkg/config/

# Run a single test
GOPROXY=off go test ./pkg/resolver/ -run TestParseDNSOutput_dig
```

## Architecture

JumpKit analyzes SSH jump chains. Given a JSON config of sequential hosts (bastion → internal → target), it resolves DNS through each hop in the chain and generates the correct `ssh -J` proxy-jump command.

**Entry point** (`cmd/jumpkit/main.go`): Parses CLI flags with `go-arg`, dispatches to TUI or CLI mode. CLI mode (`-c config.json`) optionally connects (`-x`) or opens a SOCKS tunnel (`-p <port>`). TUI mode runs a Bubbletea full-screen terminal UI for interactively editing, saving, and running jump chains.

**Core types** (`pkg/core/types.go`): `HopConfig` (host, port, user, auth, DNS toggle), `AnalysisResult` (resolved chain + generated SSH commands), `SSHCommand` (raw command + display variant). No behavior — pure data + formatting.

**Analyzer** (`pkg/analyzer/analyzer.go`): The main pipeline. Iterates hops in order, building a proxy-jump chain. For each hop, it SSHes in and runs a DNS command (`dig`/`nslookup`/`getent`) against the target hostname. Hops with `use_internal_dns: true` skip DNS and just test connectivity with `echo ok`. Stops DNS at the first hop that resolves successfully. Multi-hop chains: `ssh -J user@hop1:22,user@hop2:22 user@target`.

**Resolver** (`pkg/resolver/resolver.go`): Picks the first available DNS tool (`dig` → `nslookup` → `getent`), formats the shell command with shell-escaped target, and parses each tool's output format to extract IP addresses.

**Executor** (`pkg/executor/`): SSH command execution split across build-tagged files. `ssh_unix.go` handles password auth via temp SSH_ASKPASS scripts and uses `Setsid` for process isolation. `ssh_windows.go` pipes passwords via stdin and hides the console window. The `Execute` method runs non-interactive remote commands; `Connect` runs an interactive SSH session. `buildSSHArgs` and `shellSplit` are in the unix file but shared by both platforms via build tags (not `//go:build ignore`).

**Config** (`pkg/config/config.go`): Load/save JSON configs (`{"hops": [...]}`). `SavePath` resolves a name to `name.json`; absolute paths are allowed, relative/directory traversal paths are rejected.

**TUI** (`pkg/tui/model.go`): Full Bubbletea TUI. Vim keybindings (hjkl), inline table editing with select popups for enum fields (auth type, DNS y/n), save (`ctrl+s`), run analysis (`r`), then connect (`x`) or tunnel (`p`) post-analysis. The `channelWriter` bridges the logger's output into the TUI's message channel for live log streaming.

**Logger** (`pkg/logger/logger.go`): Thread-safe leveled logger writing to stderr (or a custom `io.Writer`). Levels: Debug < Info < Warn < Error. `Step()` prints `[N/T]` prefixed lines; `Section()` prints a ruled header.

## Dependencies

- **bubbletea + lipgloss**: TUI framework and styling
- **go-arg**: Struct-tag-based CLI flag parsing
- **x/term**: Password input in CLI mode

## Notes

- The `jumpkit` binary in the repo root is a built artifact and gitignored.
- Config files are `.json` with a `"hops"` array. Auth tokens (passwords, key paths) are stored in-memory only and never serialized to JSON.
- `test.json` in the repo root is an example/test config, not tracked in git.
