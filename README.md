# shhx

`shhx` is a live encrypted secret handoff tool.

It is built for the narrow case where one browser creates a secret, stays online, and hands it directly to another browser over a live peer connection. There is no account system, no database, and no server-side secret storage.

## Features

- no login
- no signup
- no server database
- no persisted secret storage on the server
- live share links like `/<secret-id>`
- browser-side encryption before payload delivery
- hidden OpenPGP envelope layered on top of live delivery
- direct browser-to-browser transfer over WebRTC
- optional delete-on-read
- optional passphrase factor
- optional authenticator-code factor
- optional TTL auto-wipe
- local browser persistence for the sender feed
- local encrypted feed export/import
- bulk owner actions for toggle, email, and delete
- embedded frontend assets in the final binary

## Architecture

`shhx` uses:

- Go 1.25
- embedded HTML, CSS, and browser-side JavaScript
- browser-side Web Crypto
- an in-memory signaling layer
- direct browser-to-browser transfer over WebRTC
- local browser storage for sender-side encrypted feed state

The server only serves the app shell and coordinates signaling. The server does not store secret payloads in a database, on disk, or in any durable queue.

## No Database

There is no backend database whatsoever.

What the server keeps:

- the current in-memory room/session state
- transient signaling messages needed to bring peers together

What the server does not keep:

- secret plaintext
- durable encrypted secret archives
- user accounts
- user sessions
- secret history

If the sender disconnects, the live handoff stops. `shhx` is not an offline dropbox.

## Security Model

- the browser generates a local anonymous identity
- the sender secret is encrypted client-side
- the payload is wrapped in a hidden OpenPGP envelope before live transport
- the OpenPGP library is browser-side only and loaded from embedded assets
- there is no server-side GPG process and no server-side key storage
- the decryption factor can include:
  - nothing extra
  - a passphrase
  - the current authenticator code
- owner-side local feed storage is encrypted at rest in the browser
- feed exports are encrypted locally with a user-supplied password before download
- the server only sees metadata needed for live signaling
- request limits, validation, rate limiting, and strict security headers are enabled on the HTTP side
- `/healthz` returns only minimal service health, never room or secret data

## Access Control

Possession of the live link is the access factor on the receiving side. The
sender validates the recipient browser identity before delivering, but the
recipient does not validate the sender. Anyone who opens the link first, while
the sender is online, can receive the secret. Add a passphrase or authenticator
factor when the link itself may be exposed.

## Endpoint Caveat

`shhx` protects secrets in transit and avoids server-side secret storage, but it does not protect a compromised browser or device.

- if the browser profile is compromised, locally persisted sender-side secrets can still be exposed
- if the endpoint is compromised, decrypted plaintext can be exposed at read time
- browser extensions, malware, shoulder-surfing, and clipboard leakage remain out of scope

## Current Limits

- both sides must be online at the same time
- connectivity depends on browser WebRTC support and network conditions
- restrictive networks can still break peer connectivity without a working TURN relay
- there is no account recovery
- there is no offline delivery

## Run

```bash
make run
```

Open `http://localhost:8194`.

## Build

```bash
make build
```

The final binary embeds the generated frontend assets.

## Deployment

- the files in `deploy/` are examples, not production-specific infrastructure
- keep production hostnames, certificates, and provider-specific details out of the public repo
- deploy the built binary and runtime config only
- do not deploy source code to production servers

## Test

```bash
make test
```

## Project

- GitHub: `https://github.com/sanix-darker/shhx.dev`
