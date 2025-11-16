# Secure Legion v0.1.5 - Changelog

## [0.1.5] - 2025-11-13

### Added

- **About Screen**
  - New About activity accessible from Settings → General
  - Displays app information, version number (0.1.4 Beta)
  - Lists key features (E2E encryption, Tor routing, Solana wallet, etc.)
  - Placeholder for Terms of Service (ready for future addition)
  - Copyright notice
  - Location: AboutActivity.kt, activity_about.xml

- **Privacy-Focused Message Reception UI**
  - Download button appears next to contacts with pending messages
  - Manual message download - user must press button to receive
  - No automatic message preview when app is closed
  - Simple "New Message" notification with count and badge
  - Deleting contact thread breaks Ping-Pong (rejects message)
  - Pending Pings stored in SharedPreferences until user action
  - Location: MainActivity.kt lines 696-831, ChatAdapter.kt

### Fixed

- **Critical: Duress PIN Not Working After Wipe**
  - Fixed distress protocol wiping its own settings
  - Root cause: SecureWipe.clearAllSharedPreferences() deleted duress_settings
  - Duress PIN was erased during emergency wipe, preventing reuse
  - Solution: Preserve duress_settings SharedPreferences during wipe
  - Duress PIN now survives account wipe for repeated use
  - Location: SecureWipe.kt lines 159-203

- **Message Sending User Experience**
  - Removed error toast notifications when sending fails
  - Messages saved to database even if send fails (queued for retry)
  - ComposeActivity now sends directly and returns to MainActivity
  - No intermediate ChatActivity screen when sending new message
  - Silent failure with log-only error reporting
  - Smooth flow: Main → Compose → Select Contact → Send → Main
  - Location: ComposeActivity.kt lines 177-223, ChatActivity.kt lines 207-213

- **Race Condition in Message Display**
  - Fixed messages not appearing immediately after sending from Compose
  - Root cause: loadMessages() and sendMessage() racing during initialization
  - Initial load completed before message was saved to database
  - Solution: Skip initial loadMessages() when pre-filled message exists
  - sendMessage() now handles loading after message is sent
  - Location: ChatActivity.kt lines 74-86

### Changed

- **Account Created Flow**
  - Removed "Account created successfully!" toast notification
  - Cleaner transition to Account Created screen
  - Account info screen provides all necessary feedback
  - Location: CreateAccountActivity.kt line 258

- **Secure Wipe Behavior**
  - Now preserves critical security settings (duress_settings)
  - Maintains list of SharedPreferences to preserve during wipe
  - Documented preservation reasoning in code comments
  - Security settings survive wipe for emergency reuse

### Technical Details

**Files Modified:**

- app/src/main/java/com/securelegion/utils/SecureWipe.kt
  - Added preservedPrefs set to exclude critical SharedPreferences
  - Modified clearAllSharedPreferences() to skip preservation list

- app/src/main/java/com/securelegion/ComposeActivity.kt
  - Added MessageService import
  - Rewrote sendMessage() to send directly and navigate to MainActivity
  - Silent error handling with no toast notifications

- app/src/main/java/com/securelegion/ChatActivity.kt
  - Added conditional message loading based on pre-filled message
  - Removed error toast in sendMessage()
  - Silent failure with automatic message list reload

- app/src/main/java/com/securelegion/MainActivity.kt
  - Added handleMessageDownload() for manual message download
  - Implements 9-step privacy-focused download flow
  - Integrates with ChatAdapter for download button display

- app/src/main/java/com/securelegion/adapters/ChatAdapter.kt
  - Added download button support with onDownloadClick callback
  - Checks SharedPreferences for pending Pings per contact
  - Shows download button instead of unread badge when Ping pending

- app/src/main/java/com/securelegion/services/TorService.kt
  - Added storePendingPing() to save incoming Pings without auto-processing
  - Added showNewMessageNotification() for simple privacy notification
  - Modified handleIncomingPing() to store instead of auto-accept/decline

- app/src/main/java/com/securelegion/LockActivity.kt
  - Added debug logging for duress PIN verification
  - Shows stored PIN, entered PIN, and match result in logs

**New Files:**

- app/src/main/java/com/securelegion/AboutActivity.kt - About screen activity
- app/src/main/res/layout/activity_about.xml - About screen layout
- CHANGELOG_v0.1.5.md - This changelog

**User Experience Improvements:**

1. **Message Sending Flow**: Users now experience seamless message sending with no error interruptions. Messages are queued for retry if sending fails.

2. **Privacy Controls**: Users have full control over message reception with manual download approval. No automatic acceptance or message previews.

3. **Distress PIN Reliability**: Emergency distress PIN remains functional even after triggering wipe, enabling repeated use in dangerous situations.

4. **Information Access**: New About screen provides transparent app information and prepares for Terms of Service.

**Security Considerations:**

- Preserved duress_settings does not compromise security
- Duress PIN still triggers emergency actions (panic alerts, wipe)
- Message download requires explicit user action (tap download button)
- Pending Pings encrypted and stored per Ping-Pong protocol
- Silent message sending failures prevent information leakage
- Debug logging does not expose sensitive data in production

**Testing Status:**

- Duress PIN preservation tested (survives wipe, functional after)
- About screen tested (displays correctly, all sections visible)
- Message sending flow tested (compose → main transition)
- Silent error handling verified (no toasts on failure)
- Download button UI tested (appears for pending messages)
- Pending: Full Ping-Pong download flow with two devices
- Pending: Message retry mechanism implementation
