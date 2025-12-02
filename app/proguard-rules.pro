# SecureLegion ProGuard Rules
# Complete configuration to prevent breaks while maintaining security

# ==================== GENERAL SETTINGS ====================

# Keep line numbers for crash reports (helps debugging)
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep annotations (needed for Room, WorkManager, etc.)
-keepattributes *Annotation*

# Keep generic signatures (needed for Kotlin)
-keepattributes Signature

# Keep exception info
-keepattributes Exceptions

# ==================== KOTLIN ====================

# Keep Kotlin metadata for reflection
-keep class kotlin.Metadata { *; }

# Keep only essential Kotlin intrinsics (not all internals)
-dontwarn kotlin.jvm.internal.**

# ==================== RUST JNI (CRITICAL!) ====================

# Keep ALL native methods (JNI)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep RustBridge completely intact (do NOT rename!)
-keep class com.securelegion.crypto.RustBridge {
    *;
}

# Keep all JNI-related classes
-keepclasseswithmembers class * {
    native <methods>;
}

# ==================== ROOM DATABASE ====================

# Keep all Room-related classes
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-dontwarn androidx.room.paging.**

# Keep all DAOs intact
-keep interface * extends androidx.room.Dao {
    *;
}

# Keep entity classes (Message, Contact, Wallet)
-keep @androidx.room.Entity class ** {
    *;
}

# Keep database class
-keep class com.securelegion.database.SecureLegionDatabase {
    *;
}

# Keep DAO interfaces
-keep interface com.securelegion.database.dao.** {
    *;
}

# Keep entity data classes
-keep class com.securelegion.database.entities.** {
    *;
}

# ==================== WORKMANAGER ====================

# Keep WorkManager workers
-keep class * extends androidx.work.Worker
-keep class * extends androidx.work.CoroutineWorker {
    public <init>(...);
}

# Keep SelfDestructWorker
-keep class com.securelegion.workers.SelfDestructWorker {
    public <init>(...);
}

# Keep all Workers
-keep class com.securelegion.workers.** {
    public <init>(...);
}

# ==================== OKHTTP ====================

# OkHttp platform used only on JVM and when Conscrypt dependency is available.
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# Keep OkHttp essentials (handles most automatically)
-dontwarn okhttp3.**

# ==================== TOR LIBRARIES ====================

# Keep Tor control library essentials
-keep class net.freehaven.tor.control.TorControlConnection { *; }
-keep class net.freehaven.tor.control.EventHandler { *; }
-dontwarn net.freehaven.tor.control.**

# Keep IPtProxy (Pluggable Transports) - Go library via JNI
-dontwarn IPtProxy.**

# Tor project libraries
-dontwarn org.torproject.**

# ==================== JSON / DATA CLASSES ====================

# If you parse JSON to data classes, keep field names
# Uncomment if you use JSON serialization:
# -keepclassmembers class com.securelegion.models.** {
#     *;
# }

# Keep ContactCard model
-keep class com.securelegion.models.ContactCard {
    *;
}

# ==================== CRYPTOGRAPHY LIBRARIES ====================

# BouncyCastle - keep only what we use (SHA3-256 for Tor v3 onion checksums)
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }
-keep class org.bouncycastle.jcajce.provider.digest.SHA3** { *; }
-keep class org.bouncycastle.crypto.digests.SHA3Digest { *; }
-dontwarn org.bouncycastle.**

# Lazysodium - keep only what we use
-keep class com.goterl.lazysodium.LazySodiumAndroid { *; }
-keep class com.goterl.lazysodium.SodiumAndroid { *; }
-dontwarn com.goterl.lazysodium.**

# JNA (Java Native Access) - used by Lazysodium
-dontwarn com.sun.jna.**

# Web3j (BIP39/BIP44) - keep only what we use
-keep class org.web3j.crypto.MnemonicUtils { *; }
-dontwarn org.web3j.**

# BitcoinJ (Base58) - keep only encoding for Solana addresses
-keep class org.bitcoinj.core.Base58 { *; }
-dontwarn org.bitcoinj.**

# ==================== QR CODE (ZXing) ====================

# Keep ZXing decoder and encoder
-keep class com.google.zxing.BarcodeFormat { *; }
-keep class com.google.zxing.EncodeHintType { *; }
-keep class com.google.zxing.DecodeHintType { *; }
-keep class com.google.zxing.qrcode.** { *; }
-keep class com.google.zxing.common.BitMatrix { *; }

# Keep barcode scanner view
-keep class com.journeyapps.barcodescanner.BarcodeView { *; }
-keep class com.journeyapps.barcodescanner.DecoratedBarcodeView { *; }
-keep class com.journeyapps.barcodescanner.BarcodeCallback { *; }
-keep class com.journeyapps.barcodescanner.BarcodeResult { *; }

# ==================== SQLCIPHER ====================

# Keep SQLCipher classes we use (Room handles encryption via SupportFactory)
-keep class net.sqlcipher.database.SQLiteDatabase { *; }
-keep class net.sqlcipher.database.SupportFactory { *; }
-dontwarn net.sqlcipher.**

# ==================== SECURITY ====================

# Keep EncryptedSharedPreferences (used by KeyManager)
-keep class androidx.security.crypto.EncryptedSharedPreferences { *; }
-keep class androidx.security.crypto.MasterKey { *; }

# Keep KeyManager
-keep class com.securelegion.crypto.KeyManager {
    public *;
}

# ==================== LOG REMOVAL (Security Fix: HIGH-001) ====================

# Remove ALL logging in release builds to prevent sensitive data leakage
# This includes error and warning logs that may expose:
# - Onion addresses
# - Wallet addresses
# - Contact information
# - Cryptographic operation details
# TEMPORARILY DISABLED FOR DEBUGGING
#-assumenosideeffects class android.util.Log {
#    public static int d(...);
#    public static int v(...);
#    public static int i(...);
#    public static int e(...);
#    public static int w(...);
#    public static int wtf(...);
#}

# ==================== OPTIMIZATION ====================

# Enable aggressive optimizations
-optimizationpasses 5
-allowaccessmodification

# Don't warn about missing classes from optional dependencies
-dontwarn javax.annotation.**
-dontwarn javax.inject.**
-dontwarn sun.misc.Unsafe
-dontwarn java.awt.**
-dontwarn org.slf4j.**

# ==================== PARCELABLE ====================

# Keep Parcelable implementations
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# ==================== SERIALIZABLE ====================

# Keep serialization info
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ==================== CRASH REPORTING ====================

# Keep crash info for debugging
-keepattributes LineNumberTable,SourceFile

# ==================== CUSTOM VIEWS ====================

# Keep custom view constructors
-keepclassmembers public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# ==================== R8 FULL MODE ====================

# R8 full mode is enabled by default in gradle.properties
