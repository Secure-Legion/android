plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("com.google.devtools.ksp") version "2.0.21-1.0.28"
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

    // BIP39/BIP44
    implementation("org.web3j:crypto:4.9.8")

    // HTTP Client for Pinata IPFS
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // JSON processing
    implementation("org.json:json:20231013")

    // Room Database with SQLCipher encryption
    val roomVersion = "2.6.1"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")

    // SQLCipher for database encryption
    implementation("net.zetetic:android-database-sqlcipher:4.5.4")
    implementation("androidx.sqlite:sqlite:2.4.0")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}