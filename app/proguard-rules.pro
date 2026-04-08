# SecureLegion ProGuard Rules
# Complete configuration for R8/ProGuard optimization
# Last updated: 2026-04-08
# COMPREHENSIVE AUDIT COMPLETED - DO NOT MODIFY WITHOUT REVIEW

# ==================== GENERAL SETTINGS ====================

# Keep line numbers for crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep annotations (Room, WorkManager, etc.)
-keepattributes *Annotation*

# Keep generic signatures (Kotlin, generics)
-keepattributes Signature

# Keep exception info
-keepattributes Exceptions

# Keep inner classes (needed for Kotlin lambdas and nested classes)
-keepattributes InnerClasses,EnclosingMethod

# ==================== KOTLIN ====================

# Keep Kotlin metadata for reflection
-keep class kotlin.Metadata { *; }
-keepclassmembers class kotlin.Metadata { *; }

# Keep Kotlin reflection (used by some serialization)
-keep class kotlin.reflect.** { *; }
-dontwarn kotlin.reflect.**

# Keep Kotlin coroutines
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}
-dontwarn kotlinx.coroutines.**

# Keep Kotlin standard library internals
-dontwarn kotlin.jvm.internal.**
-dontwarn kotlin.**

# ==================== RUST JNI (CRITICAL!) ====================

# Keep ALL native methods - JNI will fail if renamed
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep RustBridge completely intact (JNI callbacks)
-keep class com.securelegion.crypto.RustBridge { *; }
-keep class com.securelegion.crypto.RustBridge$* { *; }

# JNI callback interfaces - Rust calls these by method name at runtime
-keep interface com.securelegion.crypto.RustBridge$TorEventCallback { *; }
-keep interface com.securelegion.crypto.RustBridge$VoicePacketCallback { *; }
-keep interface com.securelegion.crypto.RustBridge$VoiceSignalingCallback { *; }

# Keep all classes that implement JNI callback interfaces (method names must not be obfuscated)
-keep class * implements com.securelegion.crypto.RustBridge$TorEventCallback { *; }
-keep class * implements com.securelegion.crypto.RustBridge$VoicePacketCallback { *; }
-keep class * implements com.securelegion.crypto.RustBridge$VoiceSignalingCallback { *; }

# PendingPingStore - accessed via JNI FindClass from Rust sendPing
-keep class com.securelegion.database.PendingPingStore { *; }

# ==================== APPLICATION CLASS ====================

-keep class com.securelegion.SecureLegionApplication { *; }
-keep class com.securelegion.BaseActivity { *; }
-keep class com.securelegion.BottomNavigation { *; }

# ==================== ALL ACTIVITIES (40 TOTAL - MANIFEST REFERENCED) ====================

-keep class com.securelegion.AboutActivity { *; }
-keep class com.securelegion.AcceptPaymentActivity { *; }
-keep class com.securelegion.AccountCreatedActivity { *; }
-keep class com.securelegion.AddFriendActivity { *; }
-keep class com.securelegion.AutoLockActivity { *; }
-keep class com.securelegion.BackupSeedPhraseActivity { *; }
-keep class com.securelegion.BridgeActivity { *; }
-keep class com.securelegion.ChatActivity { *; }
-keep class com.securelegion.ComposeActivity { *; }
-keep class com.securelegion.ContactOptionsActivity { *; }
-keep class com.securelegion.CreateAccountActivity { *; }
-keep class com.securelegion.CreateWalletActivity { *; }
-keep class com.securelegion.DevicePasswordActivity { *; }
-keep class com.securelegion.DuressPinActivity { *; }
-keep class com.securelegion.ImportWalletActivity { *; }
-keep class com.securelegion.LockActivity { *; }
-keep class com.securelegion.MainActivity { *; }
-keep class com.securelegion.NotificationsActivity { *; }
-keep class com.securelegion.QRScannerActivity { *; }
-keep class com.securelegion.ReceiveActivity { *; }
-keep class com.securelegion.RecentTransactionsActivity { *; }
-keep class com.securelegion.RequestDetailsActivity { *; }
-keep class com.securelegion.RequestMoneyActivity { *; }
-keep class com.securelegion.RestoreAccountActivity { *; }
-keep class com.securelegion.SecurityModeActivity { *; }
-keep class com.securelegion.SendActivity { *; }
-keep class com.securelegion.SendMoneyActivity { *; }
-keep class com.securelegion.SettingsActivity { *; }
-keep class com.securelegion.SplashActivity { *; }
-keep class com.securelegion.SwapActivity { *; }
-keep class com.securelegion.TransactionDetailActivity { *; }
-keep class com.securelegion.TransactionsActivity { *; }
-keep class com.securelegion.TransferDetailsActivity { *; }
-keep class com.securelegion.WalletActivity { *; }
-keep class com.securelegion.WalletIdentityActivity { *; }
-keep class com.securelegion.WalletSettingsActivity { *; }
-keep class com.securelegion.WelcomeActivity { *; }
-keep class com.securelegion.WipeAccountActivity { *; }

# --- Group/Community Features (added 2025-2026) ---
-keep class com.securelegion.AddAdminPickerActivity { *; }
-keep class com.securelegion.AddGroupMembersActivity { *; }
-keep class com.securelegion.BannedUsersActivity { *; }
-keep class com.securelegion.CreateGroupActivity { *; }
-keep class com.securelegion.EditAdminRightsActivity { *; }
-keep class com.securelegion.GroupAdminsActivity { *; }
-keep class com.securelegion.GroupChatActivity { *; }
-keep class com.securelegion.GroupMembersActivity { *; }
-keep class com.securelegion.GroupPermissionsActivity { *; }
-keep class com.securelegion.GroupProfileActivity { *; }
-keep class com.securelegion.RecentActionsActivity { *; }

# --- Voice Calling Features ---
-keep class com.securelegion.CallHistoryActivity { *; }
-keep class com.securelegion.CallLogActivity { *; }
-keep class com.securelegion.ContactCallActivity { *; }
-keep class com.securelegion.IncomingCallActivity { *; }
-keep class com.securelegion.NewCallActivity { *; }
-keep class com.securelegion.VoiceCallActivity { *; }

# --- Settings, System & Monitoring ---
-keep class com.securelegion.AppearanceActivity { *; }
-keep class com.securelegion.CommunicationModeActivity { *; }
-keep class com.securelegion.DeveloperActivity { *; }
-keep class com.securelegion.DeviceProtectionUnlockActivity { *; }
-keep class com.securelegion.DevicesActivity { *; }
-keep class com.securelegion.ImagePreviewActivity { *; }
-keep class com.securelegion.QrSettingsActivity { *; }
-keep class com.securelegion.SystemLogActivity { *; }
-keep class com.securelegion.TorHealthActivity { *; }

# --- Help & Legal ---
-keep class com.securelegion.HelpActivity { *; }
-keep class com.securelegion.HelpCenterActivity { *; }
-keep class com.securelegion.PrivacyPolicyActivity { *; }
-keep class com.securelegion.SupportComposerActivity { *; }
-keep class com.securelegion.TermsOfServiceActivity { *; }

# --- Test ---
-keep class com.securelegion.stresstest.StressTestActivity { *; }

# ==================== SERVICES (MANIFEST + INTENT REFERENCED) ====================

# Keep all services — many are started by intent/class name or referenced from JNI
-keep class com.securelegion.services.** { *; }

# ==================== BROADCAST RECEIVERS (MANIFEST REFERENCED) ====================

-keep class com.securelegion.receivers.** { *; }
-keep class com.securelegion.receivers.TorServiceRestartReceiver { *; }
-keep class com.securelegion.receivers.BootReceiver { *; }

# ==================== ROOM DATABASE (CRITICAL!) ====================

# Keep Room database class and generated impl
-keep class com.securelegion.database.SecureLegionDatabase { *; }
-keep class com.securelegion.database.SecureLegionDatabase_Impl { *; }

# Keep all DAOs - Room uses reflection
-keep interface com.securelegion.database.dao.** { *; }
-keep class com.securelegion.database.dao.**_Impl { *; }

# Keep all entity classes with their field names (Room maps columns to fields)
-keep @androidx.room.Entity class * { *; }
-keep class com.securelegion.database.entities.** { *; }
-keepclassmembers class com.securelegion.database.entities.** { *; }

# Entity fields - CRITICAL for Room column mapping
-keep class com.securelegion.database.entities.Contact { *; }
-keep class com.securelegion.database.entities.Message { *; }
-keep class com.securelegion.database.entities.Wallet { *; }
-keep class com.securelegion.database.entities.ReceivedId { *; }
-keep class com.securelegion.database.entities.UsedSignature { *; }
-keep class com.securelegion.database.entities.CallHistory { *; }
-keep class com.securelegion.database.entities.CallQualityLog { *; }
-keep class com.securelegion.database.entities.ContactKeyChain { *; }
-keep class com.securelegion.database.entities.CrdtOpLog { *; }
-keep class com.securelegion.database.entities.Group { *; }
-keep class com.securelegion.database.entities.GroupPeer { *; }
-keep class com.securelegion.database.entities.MessageReaction { *; }
-keep class com.securelegion.database.entities.PendingGroupDelivery { *; }
-keep class com.securelegion.database.entities.PingInbox { *; }
-keep class com.securelegion.database.entities.SkippedMessageKey { *; }

# Room type converters
-keep class com.securelegion.database.converters.** { *; }

# Room internals
-keep class * extends androidx.room.RoomDatabase
-dontwarn androidx.room.paging.**

# ==================== DATA MODELS (JSON PARSING - CRITICAL!) ====================

# These classes use JSONObject.getString("field_name") - field names MUST match JSON keys
-keep class com.securelegion.models.** { *; }
-keepclassmembers class com.securelegion.models.** { *; }

# Individual model classes with JSON parsing
-keep class com.securelegion.models.Chat { *; }
-keep class com.securelegion.models.Contact { *; }
-keep class com.securelegion.models.ContactCard { *; }
-keep class com.securelegion.models.FriendRequest { *; }
-keep class com.securelegion.models.PendingFriendRequest { *; }
-keep class com.securelegion.models.PendingPing { *; }
-keep class com.securelegion.models.AckState { *; }
-keep class com.securelegion.models.OutOfOrderBuffer { *; }
-keep class com.securelegion.models.TorHealthStatus { *; }

# Keep companion object factory methods (fromJson, toJson)
-keepclassmembers class com.securelegion.models.** {
    public static ** fromJson(...);
    public static ** toJson(...);
    public static ** Companion;
    public ** toJson();
}

# ==================== CRYPTO & PAYMENT CLASSES (CRITICAL!) ====================

# NLx402Manager - payment protocol with JSON parsing
-keep class com.securelegion.crypto.NLx402Manager { *; }
-keep class com.securelegion.crypto.NLx402Manager$* { *; }
-keep class com.securelegion.crypto.NLx402Manager$PaymentQuote { *; }
-keep class com.securelegion.crypto.NLx402Manager$VerificationResult { *; }
-keep class com.securelegion.crypto.NLx402Manager$VerificationResult$Success { *; }
-keep class com.securelegion.crypto.NLx402Manager$VerificationResult$Failed { *; }
-keepclassmembers class com.securelegion.crypto.NLx402Manager$PaymentQuote {
    public static ** fromJson(...);
    *;
}

# KeyManager - singleton accessed from Rust JNI
-keep class com.securelegion.crypto.KeyManager { *; }
-keepclassmembers class com.securelegion.crypto.KeyManager {
    public static ** getInstance(...);
    *;
}

# TorManager - Tor network management
-keep class com.securelegion.crypto.TorManager { *; }

# NLx402ReplayProtection - replay protection
-keep class com.securelegion.crypto.NLx402ReplayProtection { *; }

# ==================== WORKMANAGER WORKERS ====================

# WorkManager instantiates workers by class name reflection
-keep class * extends androidx.work.Worker { *; }
-keep class * extends androidx.work.CoroutineWorker { *; }
-keep class * extends androidx.work.ListenableWorker { *; }

# SecureLegion workers
-keep class com.securelegion.workers.** { *; }
-keep class com.securelegion.workers.MessageRetryWorker { *; }
-keep class com.securelegion.workers.ImmediateRetryWorker { *; }
-keep class com.securelegion.workers.SelfDestructWorker { *; }
-keep class com.securelegion.workers.AckWorker { *; }
-keep class com.securelegion.workers.FriendRequestWorker { *; }
-keep class com.securelegion.workers.SkippedKeyCleanupWorker { *; }
-keep class com.securelegion.workers.TapSyncWorker { *; }
-keep class com.securelegion.workers.TorHealthMonitorWorker { *; }

# ==================== RECYCLER VIEW ADAPTERS ====================

# Adapters and ViewHolder classes
-keep class com.securelegion.adapters.** { *; }
-keep class com.securelegion.adapters.ChatAdapter { *; }
-keep class com.securelegion.adapters.ChatAdapter$* { *; }
-keep class com.securelegion.adapters.ContactAdapter { *; }
-keep class com.securelegion.adapters.ContactAdapter$* { *; }
-keep class com.securelegion.adapters.MessageAdapter { *; }
-keep class com.securelegion.adapters.MessageAdapter$* { *; }
-keep class com.securelegion.adapters.TransactionAdapter { *; }
-keep class com.securelegion.adapters.TransactionAdapter$* { *; }
-keep class com.securelegion.adapters.WalletAdapter { *; }
-keep class com.securelegion.adapters.WalletAdapter$* { *; }

# New adapters (added 2025-2026)
-keep class com.securelegion.adapters.CallHistoryAdapter { *; }
-keep class com.securelegion.adapters.CallHistoryAdapter$* { *; }
-keep class com.securelegion.adapters.FriendRequestAdapter { *; }
-keep class com.securelegion.adapters.FriendRequestAdapter$* { *; }
-keep class com.securelegion.adapters.GroupAdapter { *; }
-keep class com.securelegion.adapters.GroupAdapter$* { *; }
-keep class com.securelegion.adapters.GroupMemberAdapter { *; }
-keep class com.securelegion.adapters.GroupMemberAdapter$* { *; }
-keep class com.securelegion.adapters.MediaGridAdapter { *; }
-keep class com.securelegion.adapters.MediaGridAdapter$* { *; }
-keep class com.securelegion.adapters.NewCallContactsAdapter { *; }
-keep class com.securelegion.adapters.NewCallContactsAdapter$* { *; }
-keep class com.securelegion.adapters.PhotoPreviewAdapter { *; }
-keep class com.securelegion.adapters.PhotoPreviewAdapter$* { *; }
-keep class com.securelegion.adapters.VoiceClipAdapter { *; }
-keep class com.securelegion.adapters.VoiceClipAdapter$* { *; }

# UI adapters (separate package)
-keep class com.securelegion.ui.adapters.** { *; }
-keep class com.securelegion.ui.adapters.AddToGroupAdapter { *; }
-keep class com.securelegion.ui.adapters.AddToGroupAdapter$* { *; }
-keep class com.securelegion.ui.adapters.ContactSelectionAdapter { *; }
-keep class com.securelegion.ui.adapters.ContactSelectionAdapter$* { *; }
-keep class com.securelegion.ui.adapters.GroupMessageAdapter { *; }
-keep class com.securelegion.ui.adapters.GroupMessageAdapter$* { *; }
-keep class com.securelegion.ui.adapters.SelectedMembersAdapter { *; }
-keep class com.securelegion.ui.adapters.SelectedMembersAdapter$* { *; }

# Keep all ViewHolder inner classes
-keepclassmembers class com.securelegion.adapters.**$*ViewHolder { *; }
-keepclassmembers class com.securelegion.ui.adapters.**$*ViewHolder { *; }

# ==================== UTILITY CLASSES ====================

-keep class com.securelegion.utils.** { *; }
-keep class com.securelegion.utils.ActivityExtensions { *; }
-keep class com.securelegion.utils.BadgeUtils { *; }
-keep class com.securelegion.utils.BiometricAuthHelper { *; }
-keep class com.securelegion.utils.PasswordValidator { *; }
-keep class com.securelegion.utils.PendingPingMigration { *; }
-keep class com.securelegion.utils.SecureWipe { *; }
-keep class com.securelegion.utils.ThemedToast { *; }
-keep class com.securelegion.utils.VoicePlayer { *; }
-keep class com.securelegion.utils.VoiceRecorder { *; }
-keep class com.securelegion.utils.AccountDetector { *; }
-keep class com.securelegion.utils.BrandedQrGenerator { *; }
-keep class com.securelegion.utils.DeviceProtectionGate { *; }
-keep class com.securelegion.utils.GlassBottomSheetDialog { *; }
-keep class com.securelegion.utils.GlassDialog { *; }
-keep class com.securelegion.utils.GlassEffect { *; }
-keep class com.securelegion.utils.ImagePicker { *; }
-keep class com.securelegion.utils.SessionManager { *; }
-keep class com.securelegion.utils.SupportChatRepository { *; }
-keep class com.securelegion.utils.TextGradient { *; }
-keep class com.securelegion.utils.TorHealthHelper { *; }
-keep class com.securelegion.utils.ZcashAddressDeriver { *; }

# ==================== TOR LIBRARIES (CRITICAL!) ====================

# Tor JNI service - uses native libraries
-keep class org.torproject.jni.** { *; }
-keep class org.torproject.jni.TorService { *; }
-dontwarn org.torproject.**

# OnionMasq Java bridge/events are consumed by Rust JNI callbacks and Gson reflection.
# Keep class/member names to prevent runtime breakage in Rust->Java calls and event parsing.
-keep class org.torproject.onionmasq.** { *; }
-keepclassmembers class org.torproject.onionmasq.** { *; }

# Tor control library
-keep class net.freehaven.tor.control.** { *; }
-dontwarn net.freehaven.tor.control.**

# IPtProxy (Pluggable Transports) - Go library via JNI
-keep class IPtProxy.** { *; }
-dontwarn IPtProxy.**

# ==================== ZCASH SDK (CRITICAL!) ====================

# Zcash SDK uses reflection and JNI
-keep class cash.z.ecc.** { *; }
-keep class co.electriccoin.** { *; }
-dontwarn cash.z.ecc.**
-dontwarn co.electriccoin.**

# Zcash BIP39
-keep class cash.z.ecc.android.bip39.** { *; }

# Zcash Rust libraries
-keep class cash.z.ecc.android.sdk.jni.** { *; }

# ==================== SOLANA / WEB3 ====================

# Web3j crypto (BIP39/BIP44)
-keep class org.web3j.crypto.** { *; }
-dontwarn org.web3j.**

# BitcoinJ (Base58 encoding)
-keep class org.bitcoinj.core.Base58 { *; }
-keep class org.bitcoinj.core.AddressFormatException { *; }
-dontwarn org.bitcoinj.**

# ==================== CRYPTOGRAPHY ====================

# BouncyCastle - SHA3-256 for Tor v3 onion checksums
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }
-keep class org.bouncycastle.jcajce.provider.digest.** { *; }
-keep class org.bouncycastle.crypto.digests.** { *; }
-dontwarn org.bouncycastle.**

# Lazysodium (libsodium) - X25519, ChaCha20-Poly1305
-keep class com.goterl.lazysodium.** { *; }
-keep class com.sun.jna.** { *; }
-dontwarn com.goterl.lazysodium.**
-dontwarn com.sun.jna.**

# AndroidX Security Crypto
-keep class androidx.security.crypto.** { *; }

# ==================== SQLCIPHER ====================

# SQLCipher for encrypted database
-keep class net.sqlcipher.** { *; }
-keep class net.sqlcipher.database.** { *; }
-dontwarn net.sqlcipher.**

# ==================== OKHTTP ====================

-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
-dontwarn okhttp3.**
-dontwarn okio.**

# ==================== QR CODE (ZXing) ====================

-keep class com.google.zxing.** { *; }
-keep class com.journeyapps.barcodescanner.** { *; }
-dontwarn com.google.zxing.**

# ==================== ML KIT ====================

-keep class com.google.mlkit.** { *; }
-dontwarn com.google.mlkit.**

# ==================== CAMERAX ====================

-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# ==================== PARCELABLE / SERIALIZABLE ====================

-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ==================== CUSTOM VIEWS ====================

-keepclassmembers public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# Custom views — inflated by class name in XML layouts
-keep class com.securelegion.views.** { *; }
-keep class com.securelegion.views.AvatarView { *; }
-keep class com.securelegion.views.GifPickerView { *; }
-keep class com.securelegion.views.MediaKeyboardView { *; }
-keep class com.securelegion.views.StickerPickerView { *; }

# ==================== ENUMS ====================

-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ==================== FRAGMENTS ====================

# Keep any fragments
-keep class com.securelegion.fragments.** { *; }
-keep class * extends androidx.fragment.app.Fragment

# ==================== LOG REMOVAL (Security) ====================

# Remove debug/info logging in release builds (keep w/e for crash diagnostics)
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
}

# ==================== OPTIMIZATION ====================

-optimizationpasses 5
-allowaccessmodification

# ==================== SUPPRESS WARNINGS ====================

-dontwarn javax.annotation.**
-dontwarn javax.inject.**
-dontwarn sun.misc.Unsafe
-dontwarn java.awt.**
-dontwarn org.slf4j.**
-dontwarn com.google.errorprone.annotations.**
-dontwarn org.codehaus.mojo.animal_sniffer.**
-dontwarn javax.naming.**
-dontwarn java.lang.invoke.**
-dontwarn org.checkerframework.**
-dontwarn afu.org.checkerframework.**
-dontwarn com.google.j2objc.annotations.**
-dontwarn javax.lang.model.element.Modifier

# ==================== LOTTIE (STICKER ANIMATIONS) ====================

-keep class com.airbnb.lottie.** { *; }
-dontwarn com.airbnb.lottie.**

# ==================== UCROP (IMAGE CROPPING) ====================

-keep class com.yalantis.ucrop.** { *; }
-dontwarn com.yalantis.ucrop.**
