import java.util.Properties
import java.io.FileInputStream

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("com.google.devtools.ksp") version "2.0.21-1.0.28"
}

// Load API keys from local.properties
val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(FileInputStream(localPropertiesFile))
}

android {
    namespace = "com.securelegion"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.securelegion"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Add API keys to BuildConfig
        buildConfigField("String", "PINATA_JWT", "\"${localProperties.getProperty("PINATA_JWT", "")}\"")
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // SwipeRefreshLayout
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")

    // Security - Encrypted storage
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Cryptography libraries
    implementation("com.goterl:lazysodium-android:5.1.0@aar")
    implementation("net.java.dev.jna:jna:5.13.0@aar")

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

    // QR Code generation
    implementation("com.google.zxing:core:3.5.2")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // Base58 encoding for Solana addresses
    implementation("org.bitcoinj:bitcoinj-core:0.16.2")

    // Room Database with SQLCipher encryption
    val roomVersion = "2.6.1"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")

    // SQLCipher for database encryption
    implementation("net.zetetic:android-database-sqlcipher:4.5.4")
    implementation("androidx.sqlite:sqlite:2.4.0")

    // WorkManager for background tasks
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // Tor binaries for Android (provides libtor.so)
    implementation("info.guardianproject:tor-android:0.4.8.18")

    // Tor control library for managing Tor via control port
    implementation("info.guardianproject:jtorctl:0.4.5.7")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}