# Runs cargo with the Rust toolchain on PATH.
#
# Toolchain notes for this host:
#   * The MSVC target cannot link. Visual Studio's C++ compiler is installed but
#     the Windows SDK is not, so link.exe fails with LNK1181 on kernel32.lib.
#     Use `--msvc` only once the SDK is present.
#   * The default is the GNU host toolchain, linking with the MinGW-w64 gcc
#     installed via winget (BrechtSanders.WinLibs.POSIX.UCRT).
#   * The sandbox and eBPF phases target Linux and build under WSL2 with a
#     native toolchain. Nothing here applies there.
$ErrorActionPreference = "Continue"

$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

$mingwBin = Get-ChildItem `
    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT*" `
    -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName "mingw64\bin" } |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

if ($mingwBin) { $env:PATH = "$mingwBin;$env:PATH" }

$toolchain = "stable-x86_64-pc-windows-gnu"

if ($args.Count -gt 0 -and $args[0] -eq "--msvc") {
    $toolchain = "stable-x86_64-pc-windows-msvc"
    $vcenvFile = Join-Path $PSScriptRoot "target\vcenv.txt"
    if (-not (Test-Path -LiteralPath $vcenvFile)) {
        $vcvars = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
        $out = & cmd.exe /c "call `"$vcvars`" >nul 2>&1 && set"
        $lines = foreach ($l in $out) {
            if ($l -match '^([^=]+)=(.*)$') { "$($matches[1])=$($matches[2])" }
        }
        New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot "target") | Out-Null
        Set-Content -LiteralPath $vcenvFile -Value $lines -Encoding ascii
    }
    foreach ($line in Get-Content -LiteralPath $vcenvFile) {
        if ($line -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
    $args = $args[1..($args.Count - 1)]
}

& cargo "+$toolchain" @args 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE
Write-Output "CARGO_EXIT=$code"
exit $code
