# Ping-Pong Wake Protocol

## Overview
A **serverless peer-to-peer messaging protocol** that ensures zero-metadata communication through recipient-authenticated message delivery.

**Core Innovation:** "Messages dont leave your device until the recipient proves theyre there."

## Key Features

- **Authentication-Before-Delivery** - Messages stay on senders device until recipient successfully authenticates
- **Zero-Metadata Architecture** - No servers track communication patterns or metadata
- **Tor-Only Communication** - All traffic routes through Tor v3 hidden services (.onion addresses)
- **Lightweight Wake Tokens** - 224 byte Ping / 140 byte Pong tokens instead of full messages
- **Forward Secrecy** - Ephemeral X25519 keys for each message exchange
- **End-to-End Encryption** - XChaCha20-Poly1305 authenticated encryption

## Token Structures

### Ping Token (224 bytes)



### Pong Token (121 bytes raw, ~140 serialized)



## Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Token signatures | Ed25519 | Identity proof |
| Message encryption | XChaCha20-Poly1305 | Authenticated encryption |
| Key exchange | X25519 ECDH | Ephemeral shared secret |
| Nonces | OS SecureRandom | Replay protection |
| Transport | Tor v3 Hidden Services | Network anonymity |

## Implementation

**Language:** Rust (secure-legion-core) + Kotlin (Android)

**Repository:** [Secure-Legion/secure-legion-android](https://github.com/Secure-Legion/secure-legion-android)

### Key Files

-  - Token structures
-  - Ed25519 signatures
-  - XChaCha20-Poly1305
-  - X25519 ECDH
-  - Tor hidden services
-  - Android service

## Message Types

| Type | Byte | Purpose |
|------|------|---------|
| PING | 0x01 | Wake signal |
| PONG | 0x02 | Authentication response |
| MESSAGE | 0x03 | Encrypted payload |
| TAP | 0x04 | Are you there check |
| DELIVERY_CONFIRMATION | 0x05 | Receipt |

## License

**Proprietary** - All rights reserved.

**Protocol Version:** 1.0
**Last Updated:** 2025-01-17
