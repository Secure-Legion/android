# SecureLegion ProGuard Rules
# Complete configuration for R8/ProGuard optimization
# Last updated: 2024
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

# ==================== SERVICES (MANIFEST + INTENT REFERENCED) ====================

-keep class com.securelegion.services.TorService { *; }
-keep class com.securelegion.services.DownloadMessageService { *; }
-keep class com.securelegion.services.MessageService { *; }
-keep class com.securelegion.services.SolanaService { *; }
-keep class com.securelegion.services.ZcashService { *; }
-keep class com.securelegion.services.ContactCardManager { *; }
-keep class com.securelegion.services.CrustService { *; }

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

# Keep all ViewHolder inner classes
-keepclassmembers class com.securelegion.adapters.**$*ViewHolder { *; }

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

# ==================== TOR LIBRARIES (CRITICAL!) ====================

# Tor JNI service - uses native libraries
-keep class org.torproject.jni.** { *; }
-keep class org.torproject.jni.TorService { *; }
-dontwarn org.torproject.**

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
