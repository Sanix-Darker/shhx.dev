# Contributor Guide

## Setup

Requirements:
- Go 1.25+

Commands:

```bash
make fmt
make assets
make test
make run
```

## Scope

Keep the project narrow:
- live two-peer rooms
- browser-side encryption
- no server-side secret persistence
- minimal UI

## Rules

- Prefer the standard library where practical.
- Keep the server state in memory only.
- Do not add a database unless the project goals change.
- Avoid external runtime dependencies unless they buy clear reliability or security value.

## Pull Requests

- Run `make fmt test build` before opening a PR.
- Document behavior changes in `README.md` when needed.
- Keep frontend additions small and local to the embedded asset files.
- Edit readable source in `internal/app/assets/`; generated embedded assets are rebuilt by `make assets`.
