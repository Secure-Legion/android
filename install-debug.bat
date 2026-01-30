@echo off
set JAVA_HOME=C:\Program Files\Android\Android Studio\jbr
set ADB=C:\Users\Eddie\AppData\Local\Android\Sdk\platform-tools\adb.exe

REM Usage: install-debug.bat [flavor] [device_id]
REM   install-debug.bat master           - install master to all devices
REM   install-debug.bat googleplay 59041 - install googleplay to specific device
REM   install-debug.bat                  - install master to all devices (default)

set FLAVOR=%1
if "%FLAVOR%"=="" set FLAVOR=master

set APK_PATH=app\build\outputs\apk\%FLAVOR%\debug\app-%FLAVOR%-debug.apk

if not exist "%APK_PATH%" (
    echo APK not found: %APK_PATH%
    echo Run "build-debug.bat %FLAVOR%" first.
    exit /b 1
)

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
