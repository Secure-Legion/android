param(
    [string]$AndroidNdk = 'C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $root
$crate = Join-Path $root 'portable-source\mobile\group-native'
$out = Join-Path $root 'dist\android'
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
$env:PATH = "$cargoBin;$env:PATH"
$env:ANDROID_NDK_HOME = $AndroidNdk
Push-Location $crate
try {
    & (Join-Path $cargoBin 'cargo.exe') ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o $out build --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Group native build failed' }
} finally {
    Pop-Location
}
foreach ($abi in @('arm64-v8a', 'armeabi-v7a', 'x86_64')) {
    $source = Join-Path $out "$abi\libsecure_group_mobile.so"
    if (!(Test-Path -LiteralPath $source)) { throw "Missing group library for $abi" }
    $destination = Join-Path $repo "app\src\main\jniLibs\$abi\libsecure_group_mobile.so"
    Copy-Item -LiteralPath $source -Destination $destination
}
