import java.util.Properties
import java.io.FileInputStream

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("com.google.devtools.ksp") version "2.3.2"
}

// Load keystore properties
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

android {
    namespace = "com.securelegion"
    compileSdk = 36

    flavorDimensions += "version"

    defaultConfig {
        applicationId = "com.securelegion"
        minSdk = 27  // Increased from 26 for Zcash SDK compatibility
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    productFlavors {
        create("master") {
            dimension = "version"
            applicationId = "com.securelegion.master"
            versionNameSuffix = "-master"

            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "true")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "true")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "true")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "true")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "true")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "true")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "true")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Master\"")
        }

        create("solanadapp") {
            dimension = "version"
            applicationId = "com.securelegion.solana"
            versionNameSuffix = "-solana"

            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "true")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "false")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "true")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "false")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Solana dApp\"")
        }

        create("solanahackathon") {
            dimension = "version"
            applicationId = "com.securelegion.solana.hackathon"
            versionNameSuffix = "-solana-hackathon"

            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "true")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "false")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "true")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "true")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Solana Hackathon\"")
            buildConfigField("String", "HACKATHON_NAME", "\"Solana\"")
        }

        create("starnethackathon") {
            dimension = "version"
            applicationId = "com.securelegion.starnet.hackathon"
            versionNameSuffix = "-starnet-hackathon"

            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "true")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "true")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "true")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "true")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Starnet Hackathon\"")
            buildConfigField("String", "HACKATHON_NAME", "\"Starnet\"")
        }

        create("googleplay") {
            dimension = "version"
            applicationId = "com.securelegion"

            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "true")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "true")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "true")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "false")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Google Play\"")
        }

        create("googleplaydemo") {
            dimension = "version"
            applicationId = "com.securelegion.demo"
            versionNameSuffix = "-demo"

            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "true")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "true")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "true")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "false")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "true")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Google Play Demo\"")
            buildConfigField("String", "DEMO_USERNAME", "\"google_reviewer\"")
            buildConfigField("String", "DEMO_PASSWORD", "\"demo123!\"")
        }

        create("fdroid") {
            dimension = "version"
            applicationId = "com.securelegion.fdroid"
            versionNameSuffix = "-fdroid"

            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "true")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "true")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "true")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "true")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"F-Droid\"")
        }
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
        resources {
            excludes += setOf(
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE",
                "META-INF/LICENSE.txt",
                "META-INF/license.txt",
                "META-INF/NOTICE",
                "META-INF/NOTICE.txt",
                "META-INF/notice.txt",
                "META-INF/*.kotlin_module",
                "META-INF/INDEX.LIST"
            )
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true  // Enable ProGuard to strip logs and optimize code
            isShrinkResources = true  // Remove unused resources
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Core library desugaring (required by Zcash SDK for Java 8+ APIs on older Android)
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // Splash Screen API (Android 12+)
    implementation("androidx.core:core-splashscreen:1.0.1")

    // SwipeRefreshLayout
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")

    // Security - Encrypted storage
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Biometric authentication
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    // Cryptography libraries (5.2.0+ has 16KB-aligned libsodium.so)
    implementation("com.goterl:lazysodium-android:5.2.0@aar")
    implementation("net.java.dev.jna:jna:5.17.0@aar")  // Updated for 16KB page size support

    // BouncyCastle for SHA3-256 (Tor v3 onion address checksum) - must be first
    implementation("org.bouncycastle:bcprov-jdk15to18:1.69")

    // BIP39/BIP44 - exclude BouncyCastle to use our version above
    implementation("org.web3j:crypto:4.9.8") {
        exclude(group = "org.bouncycastle")
    }

    // HTTP Client for Pinata IPFS
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // JSON processing
    implementation("org.json:json:20231013")
    implementation("com.google.code.gson:gson:2.10.1")

    // QR Code generation
    implementation("com.google.zxing:core:3.5.2")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // CameraX for QR scanning (1.4.0+ required for 16KB page size support)
    val cameraxVersion = "1.4.0"
    implementation("androidx.camera:camera-core:$cameraxVersion")
    implementation("androidx.camera:camera-camera2:$cameraxVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraxVersion")
    implementation("androidx.camera:camera-view:$cameraxVersion")

    // ML Kit Barcode Scanning (latest version)
    implementation("com.google.mlkit:barcode-scanning:17.3.0")

    // Base58 encoding for Solana addresses
    implementation("org.bitcoinj:bitcoinj-core:0.16.2")

    // Zcash Android SDK for wallet functionality (latest 2025 version)
    implementation("cash.z.ecc.android:zcash-android-sdk:2.4.0")

    // Zcash BIP39 library (required for seed phrase handling)
    implementation("cash.z.ecc.android:kotlin-bip39:1.0.9")

    // Room Database with SQLCipher encryption
    val roomVersion = "2.7.0-alpha11"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")

    // SQLCipher for database encryption (modern package with 16KB support + active security updates)
    implementation("net.zetetic:sqlcipher-android:4.6.1")
    implementation("androidx.sqlite:sqlite:2.4.0")

    // WorkManager for background tasks
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // Lifecycle for app background/foreground detection
    implementation("androidx.lifecycle:lifecycle-process:2.8.7")
    implementation("androidx.lifecycle:lifecycle-common:2.8.7")

    // Tor binaries for Android (provides libtor.so)
    implementation("info.guardianproject:tor-android:0.4.8.21")

    // Tor control library for managing Tor via control port
    implementation("info.guardianproject:jtorctl:0.4.5.7")

    // Pluggable Transports for bridges (obfs4, snowflake, meek)
    // IPtProxy includes obfs4proxy, snowflake, and meek_lite pluggable transports
    implementation("com.netzarchitekten:IPtProxy:4.2.2")

    // Voice Calling - Opus codec for audio compression
    // Using native Rust implementation via RustBridge (libopus built from source)

    // Coroutines for async voice call handling (if not already included via core-ktx)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}