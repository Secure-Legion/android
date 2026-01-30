@echo off
set JAVA_HOME=C:\Program Files\Android\Android Studio\jbr
set ADB=C:\Users\Eddie\AppData\Local\Android\Sdk\platform-tools\adb.exe

REM Usage: build-and-install.bat [flavor] [device_id]
REM   build-and-install.bat master           - build & install master to all devices
REM   build-and-install.bat googleplay 59041 - build & install googleplay to specific device
REM   build-and-install.bat                  - build & install master to all devices (default)

set FLAVOR=%1
if "%FLAVOR%"=="" set FLAVOR=master

echo Building %FLAVOR% debug APK...
call gradlew.bat assemble%FLAVOR%Debug
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

set APK_PATH=app\build\outputs\apk\%FLAVOR%\debug\app-%FLAVOR%-debug.apk

echo.
if "%2"=="" (
    echo Installing %FLAVOR% to all connected devices...
    for /f "skip=1 tokens=1" %%d in ('"%ADB%" devices') do (
        if not "%%d"=="" (
            echo Installing to %%d...
            "%ADB%" -s %%d install -r "%APK_PATH%"
        )
    )
) else (
    echo Installing %FLAVOR% to %2...
    "%ADB%" -s %2 install -r "%APK_PATH%"
)
