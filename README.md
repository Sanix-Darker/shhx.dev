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
- direct browser-to-browser transfer over WebRTC
- optional delete-on-read
- optional passphrase factor
- optional authenticator-code factor
- optional TTL auto-wipe
- local browser persistence for the sender feed
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
- the decryption factor can include:
  - nothing extra
  - a passphrase
  - the current authenticator code
- owner-side local feed storage is encrypted at rest in the browser
- the server only sees metadata needed for live signaling
- request limits, validation, rate limiting, and strict security headers are enabled on the HTTP side

## Current Limits

- both sides must be online at the same time
- connectivity depends on browser WebRTC support and network conditions
- restrictive networks can still break peer connectivity
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

## Test

```bash
make test
```

## Project

- GitHub: `https://github.com/sanix-darker/shhx.dev`
