@echo off
echo Building Secure Legion Core Library for Android...
echo.

REM Check if cargo-ndk is installed
where cargo-ndk >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: cargo-ndk not found!
    echo Please install it with: cargo install cargo-ndk
    exit /b 1
)

REM Check if ANDROID_NDK_HOME is set
if not defined ANDROID_NDK_HOME (
    echo ERROR: ANDROID_NDK_HOME environment variable not set!
    echo Please set it to your NDK path, for example:
    echo set ANDROID_NDK_HOME=C:\Users\YourName\AppData\Local\Android\Sdk\ndk\26.1.10909125
    exit /b 1
)

echo Building for ARM64 (arm64-v8a)...
cargo ndk --target aarch64-linux-android --platform 26 build --release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: ARM64 build failed!
    exit /b 1
)

echo.
echo Building for ARMv7 (armeabi-v7a)...
cargo ndk --target armv7-linux-androideabi --platform 26 build --release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: ARMv7 build failed!
    exit /b 1
)

echo.
echo Building for x86_64 (for emulator support)...
cargo ndk --target x86_64-linux-android --platform 26 build --release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: x86_64 build failed!
    exit /b 1
)

echo.
echo Build successful!
echo.
echo Copying libraries to Android project...

REM Create jniLibs directories if they don't exist
if not exist "..\app\src\main\jniLibs\arm64-v8a" (
    mkdir "..\app\src\main\jniLibs\arm64-v8a"
)
if not exist "..\app\src\main\jniLibs\armeabi-v7a" (
    mkdir "..\app\src\main\jniLibs\armeabi-v7a"
)
if not exist "..\app\src\main\jniLibs\x86_64" (
    mkdir "..\app\src\main\jniLibs\x86_64"
)

REM Copy libraries
copy /Y "target\aarch64-linux-android\release\libsecurelegion.so" "..\app\src\main\jniLibs\arm64-v8a\"
copy /Y "target\armv7-linux-androideabi\release\libsecurelegion.so" "..\app\src\main\jniLibs\armeabi-v7a\"
copy /Y "target\x86_64-linux-android\release\libsecurelegion.so" "..\app\src\main\jniLibs\x86_64\"

echo.
echo Done! Libraries copied to:
echo   - app/src/main/jniLibs/arm64-v8a/libsecurelegion.so
echo   - app/src/main/jniLibs/armeabi-v7a/libsecurelegion.so
echo   - app/src/main/jniLibs/x86_64/libsecurelegion.so
echo.
echo You can now build the Android app in Android Studio!
pause
