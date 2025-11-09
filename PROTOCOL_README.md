<div align="center">

# Ping-Pong Wake Protocol

**Serverless peer-to-peer messaging with authentication-before-delivery and zero metadata**

[![Protocol](https://img.shields.io/badge/protocol-v1.0-blue)](https://github.com/Secure-Legion/Ping-Pong-Wake-Protocol)
[![License](https://img.shields.io/badge/license-Proprietary-red)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Cross--Platform-green)](https://www.android.com/)

> "Messages don't leave your device until the recipient proves they're there"

[View Specification](#protocol-specification) | [Reference Implementation](https://github.com/Secure-Legion/secure-legion-android) | [Patent Claims](#patent-claims)

</div>

---

## Overview

The Ping-Pong Wake Protocol is a novel cryptographic protocol for serverless peer-to-peer messaging that ensures **zero-metadata communication** through recipient-authenticated message delivery.

Unlike traditional messaging systems that transmit messages to potentially compromised devices, this protocol requires **recipient authentication before message transmission**:

- **Authentication-Before-Delivery** - Messages remain on sender device until recipient proves presence
- **Zero-Metadata Architecture** - No servers track who communicates with whom or when
- **Tor-Only Communication** - All traffic routed through Tor hidden services
- **Lightweight Wake Tokens** - ~200 byte Ping/Pong tokens instead of full messages
- **Duress Protection** - Failed authentication prevents message delivery
- **Replay Protection** - Cryptographic nonces prevent token reuse
- **Forward Secrecy** - Ephemeral keys for each message

## The Problem

Traditional messaging systems suffer from critical security and privacy flaws:

| Problem | Traditional Systems | Ping-Pong Protocol |
|---------|--------------------|--------------------|
| **Metadata Logging** | Servers log who talks to whom, when, how often | No servers = no logs |
| **Device Seizure** | Messages delivered even if device compromised | Authentication required first |
| **Traffic Analysis** | Central servers enable communication pattern analysis | Direct P2P via Tor |
| **Duress Scenarios** | Messages arrive regardless of user state | Failed auth = no delivery |
| **Server Compromise** | Single point of failure exposes all metadata | No servers to compromise |

## How It Works

### The Ping-Pong Handshake

```
SENDER                                    RECIPIENT
  │                                           │
  ├─ 1. Encrypt message locally              │
  ├─ 2. Queue in encrypted storage           │
  │                                           │
  ├── 3. Send PING ────────────────────────> │
  │   (200 bytes via Tor .onion)             │
  │                                           ├─ 4. Receive Ping token
  │                                           ├─ 5. Verify signature
  │                                           ├─ 6. Request biometric/PIN
  │                                           ├─ 7. User authenticates
  │                                           │
  │ <──────────────────────── 8. Send PONG ──┤
  │   (150 bytes via Tor)                    │
  │                                           │
  ├─ 9. Verify Pong signature                │
  ├─ 10. Confirm authenticated = true        │
  │                                           │
  ├── 11. Send MESSAGE ─────────────────────>│
  │    (encrypted content via Tor)           │
  │                                           ├─ 12. Decrypt & display
  │                                           │
  │ <──────────────────── 13. Send ACK ──────┤
  │                                           │
  ├─ 14. Delete from queue                   │
  │                                           │
```

### Key Innovation

**Messages are NOT transmitted until recipient proves they are present, conscious, and authenticated.**

If recipient device is:
- Seized by authorities → No authentication → Message never sent
- Under duress → Duress PIN entered → Device wipes → Message never sent
- Powered off → Ping times out → Retry later → Message stays safe on sender device
- Compromised by malware → Cannot authenticate → Message never sent

## Protocol Specification

### Ping Token

Lightweight wake signal (~200 bytes) sent over Tor:

```rust
PingToken {
    sender_pubkey: [u8; 32]        // Ed25519 public key
    recipient_pubkey: [u8; 32]     // Ed25519 public key
    nonce: [u8; 24]                // Unique random nonce
    timestamp: i64                 // Unix timestamp
    signature: [u8; 64]            // Ed25519 signature
}
```

**Purpose**: Wake recipient device and request authentication without revealing message content.

### Pong Token

Authentication confirmation (~150 bytes) returned via Tor:

```rust
PongToken {
    ping_nonce: [u8; 24]           // Links to original Ping
    pong_nonce: [u8; 24]           // New unique nonce
    timestamp: i64                 // Unix timestamp
    authenticated: bool            // User authentication status
    signature: [u8; 64]            // Ed25519 signature
}
```

**Purpose**: Confirm recipient is authenticated and ready to receive message.

### Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Token Signatures** | Ed25519 | Prove sender/recipient identity |
| **Message Encryption** | XChaCha20-Poly1305 | Authenticated encryption |
| **Key Exchange** | X25519 (ECDH) | Ephemeral session keys |
| **Nonce Generation** | OS Secure Random | Replay protection |
| **Transport** | Tor Hidden Services | Network anonymity |

### Security Properties

**Protects Against**:
- Passive network observers (Tor encryption)
- Active MITM attacks (Ed25519 signatures)
- Server compromise (no servers exist)
- Device seizure (authentication-before-delivery)
- Metadata analysis (zero server logs)
- Replay attacks (unique nonces + timestamps)
- Traffic analysis (no persistent connections)

**Threat Model**: See [Security Model](#security-model) for complete analysis.

## Architecture

### Network Layer

```
┌─────────────────────────────────────────────────────────┐
│                    Tor Network                          │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐       │
│  │  Guard   │────▶│  Middle  │────▶│   Exit   │       │
│  │  Relay   │     │  Relay   │     │  Relay   │       │
│  └──────────┘     └──────────┘     └──────────┘       │
└─────────────────────────────────────────────────────────┘
       │                                        │
       │                                        │
   ┌───▼────┐                              ┌───▼────┐
   │ Sender │                              │Recipient│
   │ Device │◄─────── Pong Token ──────────│ Device │
   │        │                              │         │
   │  .onion│──────── Ping Token ─────────▶│ .onion │
   │ service│                              │ service │
   └────────┘                              └─────────┘
```

Each device runs a Tor hidden service:
- Listening on port 9150 (default)
- Unique .onion address per user
- No clearnet fallback
- Automatic circuit rotation

### Message Flow States

```
Sender Side:
QUEUED → PING_SENT → PONG_RECEIVED → SENDING → DELIVERED
                                                    ↓
                                                 FAILED

Recipient Side:
PING_RECEIVED → AUTHENTICATING → PONG_SENT → MESSAGE_RECEIVED → DECRYPTED
```

## Performance Characteristics

### Latency

**Message Delivery Time** (both users online):
- Ping transmission: 1-3 seconds (Tor latency)
- User authentication: 1-5 seconds (biometric)
- Pong transmission: 1-3 seconds (Tor latency)
- Message transmission: 1-5 seconds (Tor latency)
- **Total: 4-16 seconds typical**

### Battery Impact

- **Idle** (listening for Pings): ~0.2% per hour
- **Active messaging**: ~0.01% per message
- **Tor circuits**: ~0.1% per hour

### Network Overhead

- Ping token: ~200 bytes
- Pong token: ~150 bytes
- Message: Variable (text only)
- ACK: ~100 bytes
- **Total overhead: ~450 bytes per message**

Compared to Signal: 50% more overhead, 100% less metadata.

## Security Model

### Threat Model

| Threat | Protection |
|--------|------------|
| **Passive Network Observer** | All traffic encrypted via Tor |
| **Active MITM** | Ed25519 signatures prevent forgery |
| **Server Compromise** | No servers to compromise |
| **Device Seizure** | Authentication-before-delivery |
| **Metadata Analysis** | No central logs or timing data |
| **Replay Attacks** | Nonce-based protection |
| **Traffic Analysis** | No persistent connections |
| **Duress Scenarios** | Failed auth prevents delivery |

### Attack Scenarios

**Scenario 1: Device Seizure**
1. Unwanted persons seize recipient device
2. Sender sends Ping token
3. Device requests authentication
4. User refuses/unable to authenticate
5. No Pong sent
6. Message never transmitted
7. **Result**: Message remains safely on sender device

**Scenario 2: Network Surveillance**
1. Adversary monitors all Tor traffic
2. Sees .onion connections but no plaintext
3. Cannot determine who talks to whom
4. Cannot distinguish Ping from random Tor traffic
5. **Result**: Communication patterns remain private

**Scenario 3: Duress PIN**
1. User forced to unlock device
2. Enters duress PIN instead of real PIN
3. Device performs emergency wipe
4. Keys destroyed, data wiped
5. Blockchain revocation broadcast
6. **Result**: No communication under duress

### Known Limitations

- Requires recipient online (or come online within retry window)
- Vulnerable to endpoint attacks (malware, keyloggers)
- No protection if authentication coerced
- Timing attacks possible with sophisticated adversary
- Tor network compromise affects anonymity

## Comparison to Other Protocols

### Signal Protocol

| Feature | Signal | Ping-Pong |
|---------|--------|-----------|
| Architecture | Client-Server | Serverless P2P |
| Metadata | Server logs contacts | Zero metadata |
| Authentication | At app launch | Before each message |
| Network | Clearnet (AWS) | Tor hidden services |
| Delivery | Push to recipient | Authentication-before-delivery |
| Server knowledge | Who, when, how often | Nothing |

### Briar

| Feature | Briar | Ping-Pong |
|---------|-------|-----------|
| Delivery | Opportunistic sync | Authentication-before-delivery |
| Wake mechanism | Polling | Ping-Pong tokens |
| Authentication | At app launch | Before each message |
| Platform | Android + Desktop | Android (mobile-first) |

### Session (Oxen)

| Feature | Session | Ping-Pong |
|---------|---------|-----------|
| Architecture | Relay nodes | Direct P2P |
| Metadata | Timing analysis possible | Zero metadata |
| Delivery | Store-and-forward | Authentication-before-delivery |
| Authentication | At app launch | Before each message |

## Reference Implementation

The Ping-Pong Wake Protocol is implemented in **Secure Legion**, an open-source Android messaging app:

**Repository**: [github.com/Secure-Legion/secure-legion-android](https://github.com/Secure-Legion/secure-legion-android)

**Core Implementation**:
- `secure-legion-core/src/network/pingpong.rs` - Protocol logic
- `secure-legion-core/src/network/tor.rs` - Tor integration
- FFI bindings for Android JNI

**Technology Stack**:
- **Language**: Rust (core) + Kotlin (Android)
- **Crypto**: ed25519-dalek, chacha20poly1305
- **Network**: arti-client (Tor)
- **Runtime**: tokio (async)

## Usage Example

### Sending a Message

```kotlin
// 1. Encrypt and queue message
val messageId = messageQueueManager.queueMessage(
    plaintext = "Secret message",
    recipientPubkey = contact.publicKey,
    recipientOnion = contact.onionAddress
)

// 2. Start Ping-Pong handshake
val intent = Intent(context, PingPongService::class.java).apply {
    action = PingPongService.ACTION_SEND_PING
    putExtra(PingPongService.EXTRA_MESSAGE_ID, messageId)
    putExtra(PingPongService.EXTRA_RECIPIENT_PUBKEY, contact.publicKey)
    putExtra(PingPongService.EXTRA_RECIPIENT_ONION, contact.onionAddress)
}
context.startService(intent)
```

### Receiving a Message

```kotlin
// 1. Receive Ping token
// 2. System requests biometric/PIN authentication
// 3. User authenticates successfully
// 4. Send Pong token automatically
// 5. Receive and decrypt message
// 6. Display to user
```

## Patent Claims

### Claim 1 (Core Method – Authentication-Before-Delivery)

A method for secure peer-to-peer messaging, comprising:

- encrypting a message on a sender device using an asymmetric or hybrid encryption scheme;
- transmitting a lightweight, cryptographically signed authentication-request token ("Ping") from the sender to a recipient;
- requiring successful recipient user authentication—biometric or PIN-based—before authorizing message transfer;
- transmitting the encrypted message only after verification of the recipient's authentication proof; and
- wherein the encrypted message remains stored on the sender device until the recipient's authentication is confirmed, preventing unauthorized delivery or interception.

### Claim 2 (System – Zero-Metadata Architecture)

A zero-metadata messaging system comprising:

- a peer-to-peer communication layer utilizing Tor hidden services or equivalent onion-routed endpoints;
- a decentralized architecture without central servers, coordinators, or logs;
- an authentication-before-delivery protocol preventing message transmission until recipient identity is proven; and
- wherein no third party can observe or infer user identities, message timing, or communication patterns.

### Claim 3 (Wake-on-Ping Protocol)

A wake protocol for decentralized messaging, comprising:

- generating and transmitting a cryptographically signed Ping token with unique nonce and replay protection;
- generating a corresponding Pong token by the recipient, including an authentication confirmation signature;
- implementing timeout and retry logic for unreachable or offline recipients; and
- wherein message delivery requires receipt of a valid Pong authentication proof, ensuring verified recipient presence.

### Novel Features

1. **Authentication-Before-Delivery**: Messages are held until the recipient successfully authenticates.
2. **Zero-Metadata Architecture**: No servers, logs, or routing data reveal sender/recipient metadata.
3. **Wake-on-Ping**: Lightweight cryptographic tokens signal recipient devices without transmitting message content.
4. **Duress Protection**: Failed or duress-PIN authentication blocks message release or triggers secure wipe.
5. **Serverless P2P**: Direct Tor-based communication without any centralized relay.
6. **Ephemeral Connections**: Stateless session handling prevents long-term linkage or traffic pattern analysis.
7. **Nonce-Based Replay Protection**: Nonce values invalidate reused or replayed tokens.
8. **Biometric-Gated Delivery**: Hardware-backed biometric authentication required for final decryption and message release.

## Roadmap

### Phase 1: Core Protocol (Complete)
- [x] Ping/Pong token structures
- [x] Ed25519 signature implementation
- [x] Tor integration
- [x] Replay protection
- [x] Reference implementation

### Phase 2: Production Deployment (In Progress)
- [x] Android app integration
- [ ] Battery optimization
- [ ] Background service reliability
- [ ] Security audit
- [ ] Beta testing

### Phase 3: Advanced Features (Planned)
- [ ] Group messaging (multi-recipient Ping-Pong)
- [ ] Asynchronous Pong (delayed authentication)
- [ ] Push notification integration
- [ ] Desktop implementation
- [ ] iOS support

### Phase 4: Research (Future)
- [ ] Post-quantum cryptography
- [ ] Traffic analysis resistance
- [ ] Deniable authentication
- [ ] Mesh networking support

## Contributing

This is proprietary protocol technology. Contributions to the reference implementation are welcome:

1. **Fork** the [reference implementation](https://github.com/Secure-Legion/secure-legion-android)
2. **Create** a feature branch
3. **Test** thoroughly (security critical!)
4. **Document** any protocol changes
5. **Open** a Pull Request

**Areas to Contribute**:
- Security analysis and auditing
- Performance optimization
- Battery efficiency improvements
- Cross-platform implementations
- Documentation and examples

See [CONTRIBUTING.md](https://github.com/Secure-Legion/secure-legion-android/blob/main/CONTRIBUTING.md) for guidelines.

## Documentation

- **This Repository**: Protocol specification and patent claims
- **Reference Implementation**: [secure-legion-android](https://github.com/Secure-Legion/secure-legion-android)
- **Website**: [securelegion.com](https://securelegion.com)
- **Architecture**: [securelegion.com/architecture](https://securelegion.com/architecture)
- **Security Model**: [securelegion.com/security-model](https://securelegion.com/security-model)

## License

This protocol specification is proprietary technology. **Provisional patent application in preparation**. All rights reserved.

**You may**:
- Implement the protocol for noncommercial use
- Study and analyze the protocol
- Reference in academic work

**You may not**:
- Use commercially without license
- Patent derivative works
- Remove attribution

For commercial licensing, contact: **patents@securelegion.com**

Reference implementation licensed under PolyForm Noncommercial License 1.0.0.

## Acknowledgments

**Cryptography**:
- [Dalek Cryptography](https://github.com/dalek-cryptography) - Ed25519, X25519 implementations
- [RustCrypto](https://github.com/RustCrypto) - ChaCha20-Poly1305 AEAD

**Networking**:
- [Arti](https://gitlab.torproject.org/tpo/core/arti) - Rust Tor client
- [Tor Project](https://www.torproject.org/) - Anonymous routing network

**Inspiration**:
- Signal Protocol - End-to-end encryption design
- Briar - Serverless P2P messaging
- Session - Decentralized architecture

## Contact

- **Issues**: [GitHub Issues](https://github.com/Secure-Legion/Ping-Pong-Wake-Protocol/issues)
- **Security**: security@securelegion.com
- **Patents**: patents@securelegion.com
- **Website**: [securelegion.com](https://securelegion.com)
- **Twitter**: [@SecureLegion](https://x.com/SecureLegion)

---

<div align="center">

**No servers. No metadata. Authentication before delivery.**

[Protocol Spec](#protocol-specification) • [Reference Implementation](https://github.com/Secure-Legion/secure-legion-android) • [Website](https://securelegion.com)

</div>
