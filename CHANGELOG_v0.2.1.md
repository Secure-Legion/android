# Changelog - Version 0.2.1

**Release Date:** November 16, 2025

## Voice Messaging System

### New Features
- **Voice Message Support**: Send and receive encrypted voice messages via Ping-Pong protocol
  - Hold mic button to record (iPhone-style UI)
  - AAC format encoding (44.1kHz, 64kbps)
  - Real-time recording timer and waveform visualization
  - Play/pause controls with progress tracking
  - Duration display on message bubbles

### Voice Message Infrastructure
- **Message Type Detection**: Implemented classification system for message types
  - TEXT messages: `0x00` type byte
  - VOICE messages: `0x01` byte + 4-byte duration
  - Backwards compatible with legacy messages

- **VoiceRecorder.kt**: Audio recording utility
  - MediaRecorder integration
  - AAC format conversion
  - Local file storage management

- **VoicePlayer.kt**: Audio playback utility
  - MediaPlayer integration
  - Progress callbacks for UI updates
  - Play/pause state management

### Database Changes
- **Migration 6→7**: Added voice message fields to Message entity
  - `messageType`: TEXT or VOICE classification
  - `voiceDuration`: Recording duration in seconds
  - `voiceFilePath`: Local storage path for audio file

## Security Enhancements

### User-Specific Contact Cards
- **Per-User Encryption**: Each contact card encrypted with unique user-generated PIN
  - Prevents unauthorized contact card access
  - PIN shared separately from IPFS CID
  - No shared global encryption keys
  - Defense-in-depth approach: CID public, PIN private
- **Crust Network Integration**: Contact cards stored on decentralized IPFS via Crust
  - Replaces centralized Pinata service
  - Solana-based storage incentives
  - Permanent, censorship-resistant storage

### DOD 3-Pass Secure Deletion
Implemented DOD 5220.22-M standard secure wiping for all message deletion operations:

- **Individual Message Deletion** (ChatActivity)
  - Securely wipes voice audio files (3-pass overwrite)
  - Deletes message from encrypted database
  - VACUUMs database to compact freed space

- **Thread Deletion** (MainActivity - swipe left)
  - Securely wipes ALL voice files in conversation
  - Deletes all messages for contact
  - VACUUMs database
  - Clears pending ping data

- **Contact Deletion** (ContactOptionsActivity)
  - Securely wipes ALL voice files
  - Deletes contact and all messages
  - VACUUMs database
  - Clears pending ping data

**3-Pass Overwrite Process:**
1. Pass 1: Overwrite with `0x00` (zeros)
2. Pass 2: Overwrite with `0xFF` (ones)
3. Pass 3: Overwrite with random data
4. Delete file and VACUUM database

## Bug Fixes

### Critical Fixes
- **Voice Message Delivery**: Fixed "stuck downloading" issue
  - Increased Tor message size limit from 10KB to 10MB (tor.rs:503)
  - Allows transmission of voice messages (typical size: 30-50KB)
  - Supports up to 10MB payloads for future media types

- **Send Button Icon**: Unified send button appearance
  - Changed voice recording send button to use `ic_send` icon
  - Consistent UI between text and voice message sending

### Encryption & Decryption
- **MessageService.kt**: Added type byte prepending before encryption
  - TEXT: Prepends `0x00` byte
  - VOICE: Prepends `0x01` + 4-byte duration (big-endian)

- **TorService.kt**: Added type byte parsing after decryption
  - Detects message type from first byte
  - Extracts voice duration for VOICE messages
  - Saves voice audio to local storage
  - Creates appropriate Message entity with type/duration/filepath

## Technical Improvements

### Rust Core (secure-legion-core)
- **Message Size Limit**: Increased from 10KB to 10MB
  - File: `src/network/tor.rs` line 503-505
  - Error message updated: "Message too large (>10MB)"
  - Supports voice messages and future media types

### Debug Logging
- **MessageService**: Voice encryption logging
  - Audio byte count
  - Duration tracking
  - Encrypted payload size
  - Base64 encoded length

- **TorService**: Voice decryption logging
  - Type byte parsing details
  - First byte type detection
  - Duration extraction
  - Decryption success/failure with diagnostics

### UI Components
- **Voice Message Layouts**:
  - `item_message_voice_sent.xml`: Outgoing voice bubble
  - `item_message_voice_received.xml`: Incoming voice bubble
  - Play/pause button with progress bar
  - Duration display

- **Recording UI**:
  - Timer display (00:00 format)
  - Cancel button (trash icon)
  - Send button (matching text send icon)
  - Hidden when not recording

## Files Modified

### Kotlin/Android
- `app/src/main/java/com/securelegion/ChatActivity.kt`: Voice recording UI & playback
- `app/src/main/java/com/securelegion/MainActivity.kt`: Secure thread deletion
- `app/src/main/java/com/securelegion/ContactOptionsActivity.kt`: Secure contact deletion
- `app/src/main/java/com/securelegion/services/MessageService.kt`: Voice encryption & type bytes
- `app/src/main/java/com/securelegion/services/TorService.kt`: Voice decryption & parsing
- `app/src/main/java/com/securelegion/database/SecureLegionDatabase.kt`: MIGRATION_6_7
- `app/src/main/java/com/securelegion/database/entities/Message.kt`: Voice message fields
- `app/src/main/java/com/securelegion/adapters/MessageAdapter.kt`: Voice playback controls

### New Files
- `app/src/main/java/com/securelegion/utils/VoiceRecorder.kt`: Recording utility
- `app/src/main/java/com/securelegion/utils/VoicePlayer.kt`: Playback utility
- `app/src/main/res/layout/item_message_voice_sent.xml`: Outgoing voice bubble
- `app/src/main/res/layout/item_message_voice_received.xml`: Incoming voice bubble
- `app/src/main/res/drawable/ic_play.xml`: Play button icon
- `app/src/main/res/drawable/ic_pause.xml`: Pause button icon

### Rust Core
- `secure-legion-core/src/network/tor.rs`: Increased message size limit

### Resources
- `app/src/main/res/layout/activity_chat.xml`: Send button icon fix

## Known Issues
- None

## Upgrade Notes
- Database automatically migrates from v6 to v7
- Voice messages sent from v0.2.1 require receiver to also be on v0.2.1+
- Legacy text messages remain fully compatible

## Security Considerations
- Voice audio stored encrypted on device using Android Keystore-derived keys
- Voice messages transmitted over Tor with XChaCha20-Poly1305 AEAD encryption
- Deleted voice files cannot be forensically recovered (DOD 3-pass wipe)
- Database VACUUMing prevents SQLite free page analysis

## Performance Notes
- Voice recording: AAC encoding (minimal CPU overhead)
- Voice playback: Native MediaPlayer (hardware accelerated)
- Message size: 3-second voice clip ≈ 30-50KB encrypted
- Network: 10MB Tor message limit supports ~3 minutes of voice

---

**Build:** v0.2.1 (November 16, 2025)
**Tested On:** Android 14+ (API 34+)
**Dependencies:** Tor, SQLCipher, libsodium, Crust Network, Solana
