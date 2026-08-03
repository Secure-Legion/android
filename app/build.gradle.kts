import java.util.Properties
import java.io.FileInputStream

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    id("com.google.devtools.ksp") version "2.3.2"
}

// Load keystore properties
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

// Solana dApp Store — separate signing key required by Solana Mobile policy
// (cannot reuse Play Store signing key per docs.solanamobile.com).
val solanaKeystorePropertiesFile = rootProject.file("solana-keystore.properties")
val solanaKeystoreProperties = Properties()
if (solanaKeystorePropertiesFile.exists()) {
    solanaKeystoreProperties.load(FileInputStream(solanaKeystorePropertiesFile))
}

android {
    namespace = "com.securelegion"
    compileSdk = 36

    flavorDimensions += "version"

    defaultConfig {
        applicationId = "com.securelegion"
        minSdk = 29  // Android 10+
        targetSdk = 36
        versionCode = 33
        versionName = "1.0.0"

        // Keep the package aligned with the native build matrix. The removed legacy x86 binary
        // predates the unified JNI receiver and must not be selected at runtime.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Jupiter Ultra API key (loaded from gitignored keystore.properties)
        buildConfigField("String", "JUPITER_API_KEY",
            "\"${keystoreProperties.getProperty("jupiterApiKey", "")}\"")
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
        // Solana dApp Store has its own keystore (Solana Mobile policy forbids
        // reusing the Play Store signing key). Only the `solanadapp` flavor's
        // release variant is wired to this config.
        create("solanaDappStore") {
            if (solanaKeystorePropertiesFile.exists()) {
                storeFile = rootProject.file(solanaKeystoreProperties.getProperty("storeFile"))
                storePassword = solanaKeystoreProperties.getProperty("storePassword")
                keyAlias = solanaKeystoreProperties.getProperty("keyAlias")
                keyPassword = solanaKeystoreProperties.getProperty("keyPassword")
            }
        }
    }

    productFlavors {
        create("master") {
            dimension = "version"
            applicationId = "com.securelegion.master"
            // versionNameSuffix = "-master"

            signingConfig = signingConfigs.getByName("release")

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
            buildConfigField("boolean", "ENABLE_SHADOW_WIRE", "false")
            // Crust/IPFS mailbox — code retained for future use. No live caller today.
            buildConfigField("boolean", "ENABLE_CRUST_IPFS", "true")
            // Tor VPN (route entire device traffic through Tor). Disabled on
            // googleplay/googleplaydemo per Play Developer VPN-service policy.
            buildConfigField("boolean", "ENABLE_VPN", "true")
        }

        create("solanadapp") {
            dimension = "version"
            applicationId = "com.securelegion.solana"
            versionNameSuffix = "-solana"

            // Flag set is intentionally identical to `googleplay` — this is the
            // audited, beta-stable feature surface. Solana-specific features
            // (wallet, voice, IPFS, VPN) stay off here until they're audited and
            // ready. Solana dApp Store gets the same restricted experience as
            // Play, just shipped via a different store + signed with its own key.
            buildConfigField("boolean", "ENABLE_TOR", "true")
            buildConfigField("boolean", "ENABLE_VOICE", "false")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "false")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "false")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "false")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Solana dApp\"")
            buildConfigField("boolean", "ENABLE_SHADOW_WIRE", "false")
            buildConfigField("boolean", "ENABLE_CRUST_IPFS", "false")
            buildConfigField("boolean", "ENABLE_VPN", "false")
            // Sign with the Solana-only keystore (Solana Mobile policy forbids
            // reusing the Play Store signing key). Works because buildTypes.release
            // intentionally does NOT set a signingConfig — each flavor decides.
            signingConfig = signingConfigs.getByName("solanaDappStore")
        }


        create("starnethackathon") {
            dimension = "version"
            applicationId = "com.securelegion.starnet.hackathon"
            versionNameSuffix = "-starnet-hackathon"

            signingConfig = signingConfigs.getByName("release")

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
            buildConfigField("boolean", "ENABLE_SHADOW_WIRE", "false")
            buildConfigField("boolean", "ENABLE_CRUST_IPFS", "true")
            buildConfigField("boolean", "ENABLE_VPN", "true")
        }

        create("googleplay") {
            dimension = "version"
            applicationId = "org.securelegion"

            signingConfig = signingConfigs.getByName("release")

            buildConfigField("boolean", "ENABLE_TOR", "true")
            // Voice CALLING only — not voice messages. Voice messages use MediaRecorder
            // (AAC) via utils/VoiceRecorder.kt and remain available on this flavor.
            // Voice calling is hard-disabled at ChatActivity.kt:799 across all flavors;
            // this flag documents intent for a future flavor-gated enablement.
            buildConfigField("boolean", "ENABLE_VOICE", "false")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "false")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "false")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "false")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"Google Play\"")
            buildConfigField("boolean", "ENABLE_SHADOW_WIRE", "false")
            // Play build forbids clearnet 3rd-party API calls; Crust/IPFS stays off here.
            buildConfigField("boolean", "ENABLE_CRUST_IPFS", "false")
            // Play Developer Policy permits VpnService only for apps where VPN is
            // the core functionality. Secure is a messaging app with optional VPN —
            // disabled on Play, available in non-Play flavors (master/apk/fdroid).
            buildConfigField("boolean", "ENABLE_VPN", "false")
        }

        create("googleplaydemo") {
            dimension = "version"
            applicationId = "com.securelegion.demo"
            versionNameSuffix = "-demo"

            signingConfig = signingConfigs.getByName("release")

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
            buildConfigField("String", "FLAVOR_NAME", "\"Google Play Demo\"")
            buildConfigField("boolean", "ENABLE_SHADOW_WIRE", "false")
            buildConfigField("boolean", "ENABLE_CRUST_IPFS", "false")
            buildConfigField("boolean", "ENABLE_VPN", "false")
        }

        create("fdroid") {
            dimension = "version"
            applicationId = "com.securelegion.fdroid"
            versionNameSuffix = "-fdroid"

            signingConfig = signingConfigs.getByName("release")

            // Mirrors the googleplay flavor's feature set. Only identity fields
            // (applicationId, versionNameSuffix, FLAVOR_NAME) and any future
            // F-Droid-specific divergences differ.
            buildConfigField("boolean", "ENABLE_TOR", "true")
            // Voice CALLING only — voice messages (AAC via MediaRecorder) still work.
            buildConfigField("boolean", "ENABLE_VOICE", "false")
            buildConfigField("boolean", "ENABLE_MESHTASTIC", "false")
            buildConfigField("boolean", "ENABLE_ZCASH_WALLET", "false")
            buildConfigField("boolean", "ENABLE_SOLANA_WALLET", "false")
            buildConfigField("boolean", "ENABLE_DEVELOPER_MENU", "false")
            buildConfigField("boolean", "ENABLE_STRESS_TESTING", "false")
            buildConfigField("boolean", "ENABLE_DEBUG_LOGS", "false")
            buildConfigField("boolean", "HAS_DEMO_LOGIN", "false")
            buildConfigField("int", "MAX_GROUP_SIZE", "100")
            buildConfigField("String", "FLAVOR_NAME", "\"F-Droid\"")
            buildConfigField("boolean", "ENABLE_SHADOW_WIRE", "false")
            buildConfigField("boolean", "ENABLE_CRUST_IPFS", "false")
            buildConfigField("boolean", "ENABLE_VPN", "true")
        }
    }

    buildFeatures {
        buildConfig = true
        compose = true
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
            // NOTE: no signingConfig set here — each flavor specifies its own
            // (release vs Solana dApp Store key). See productFlavors above.
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

    // Jetpack Compose (used for M3 LoadingIndicator on create account button)
    implementation(platform("androidx.compose:compose-bom:2025.06.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

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
    implementation("org.bouncycastle:bcprov-jdk15to18:1.79")

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

    // Tor: Arti (in-process Rust) — Guardian Project C Tor deps removed
    // tor-android + jtorctl no longer needed (C Tor daemon replaced by Arti)
    // IPtProxy kept — required by OnionMasq VPN for pluggable transports
    implementation("com.netzarchitekten:IPtProxy:5.1.0")

    // Voice Calling - Opus codec for audio compression
    // Using native Rust implementation via RustBridge (libopus built from source)

    // Coroutines for async voice call handling (if not already included via core-ktx)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // Emoji panel (keyboard-replacement, Google emoji sprites, no network)
    implementation("com.vanniktech:emoji-google:0.23.0")

    // Lottie for animated sticker rendering (Noto Animated Emoji)
    implementation("com.airbnb.android:lottie:6.7.1")

    // GIF rendering in chat bubbles and GIF picker
    implementation("pl.droidsonroids.gif:android-gif-drawable:1.2.29")

    // Photo crop/rotate before sending (UCrop - battle-tested crop UI)
    implementation("com.github.yalantis:ucrop:2.2.11")

    // Photo editor (draw, text, emoji overlay before sending)
    implementation("com.burhanrashid52:photoeditor:3.0.2")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
