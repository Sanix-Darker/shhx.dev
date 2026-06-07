# Security Policy

## Scope

`shhx` is a live encrypted secret handoff tool, not a password manager and not an offline secret dropbox.

Its goals are:

- browser-side encryption before delivery
- no backend database
- no durable server-side secret storage
- live peer handoff while both sides stay online

## Threat Model

`shhx` is designed to reduce exposure from:

- server-side database leaks
- server-side durable storage compromise
- accidental server retention of secret payloads
- passive observers between peers, assuming modern browser crypto and HTTPS

## Out Of Scope

`shhx` does not protect against:

- compromised endpoints
- malicious browser extensions
- malware or keyloggers
- shoulder-surfing
- clipboard interception
- a sender or receiver intentionally leaking the plaintext
- WebRTC connectivity failures caused by hostile or restrictive networks

## Access Control

The live link is the access factor on the receiving side. The sender validates
the recipient browser identity before delivery, but the recipient does not
validate the sender, and the link grants access to whoever opens it first while
the sender is online. Treat the link as a bearer credential: deliver it over a
trusted channel, and add a passphrase or authenticator factor when the link
itself may be exposed.

When `shhx` is exposed directly to the internet rather than behind a trusted
reverse proxy, set `SHHX_TRUST_PROXY=false` so forwarded headers cannot be used
to spoof a client source IP or request scheme.

## Local Persistence

Owner-side local feed persistence is encrypted at rest in the browser, but it still depends on endpoint integrity.

If a browser profile or device is compromised, locally stored encrypted records and any decrypted plaintext shown in the UI may be exposed.

Feed export/import is local-only. The exported file is encrypted in the browser with the provided backup password before it is downloaded, and import re-encrypts restored records into the current browser vault.

## Operational Visibility

The health endpoint is intentionally minimal. It reports only service availability and must not expose room, peer, user, or secret metadata.

## Disclosure

If you find a security issue, do not open a public issue with exploit details first.

Send a private report through GitHub security advisories or contact the maintainer directly through the project profile.
