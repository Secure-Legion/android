@echo off
set JAVA_HOME=C:\Program Files\Android\Android Studio\jbr

if "%1"=="" (
    echo Building ALL flavors debug APKs...
    call gradlew.bat assembleDebug
) else (
    echo Building %1 debug APK...
    call gradlew.bat assemble%1Debug
)
