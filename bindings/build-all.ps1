# Build script for rustCrypto library on all platforms (Windows)
# This script builds the Rust library for all target platforms

$ErrorActionPreference = 'Stop'

Write-Host '===========================================' -ForegroundColor Cyan
Write-Host 'Building rustCrypto for all platforms' -ForegroundColor Cyan
Write-Host '===========================================' -ForegroundColor Cyan
Write-Host ''

# Get the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Push-Location $ProjectRoot

# Function to build for a specific target
function Build-Target {
    param(
        [string]$Target,
        [string]$Name
    )
    
    Write-Host "Building for $Name ($Target)..." -ForegroundColor Yellow
    
    # Check if target is installed
    $installedTargets = rustup target list --installed
    if (-not ($installedTargets -match "^$Target\s")) {
        Write-Host "Installing target $Target..." -ForegroundColor Gray
        rustup target add $Target
    }
    
    # Build the library
    cargo build --target $Target --release
    
    Write-Host "? Built for $Name" -ForegroundColor Green
    Write-Host ''
}

# Function to build Android libraries
function Build-Android {
    Write-Host '===========================================' -ForegroundColor Cyan
    Write-Host 'Building for Android' -ForegroundColor Cyan
    Write-Host '===========================================' -ForegroundColor Cyan
    
    $targets = @(
        @{ Target = 'aarch64-linux-android'; Name = 'Android ARM64' },
        @{ Target = 'armv7-linux-androideabi'; Name = 'Android ARMv7' },
        @{ Target = 'x86_64-linux-android'; Name = 'Android x86_64' },
        @{ Target = 'i686-linux-android'; Name = 'Android x86' }
    )
    
    foreach ($t in $targets) {
        Build-Target -Target $t.Target -Name $t.Name
    }
    
    # Copy libraries to Android project
    Write-Host 'Copying libraries to Android project...' -ForegroundColor Yellow
    
    $androidDir = Join-Path $ScriptDir 'android\src\main\cpp\libs'
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $androidDir 'arm64-v8a')
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $androidDir 'armeabi-v7a')
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $androidDir 'x86_64')
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $androidDir 'x86')
    
    Copy-Item 'target\aarch64-linux-android\release\libcrypto_lib.a' (Join-Path $androidDir 'arm64-v8a\')
    Copy-Item 'target\armv7-linux-androideabi\release\libcrypto_lib.a' (Join-Path $androidDir 'armeabi-v7a\')
    Copy-Item 'target\x86_64-linux-android\release\libcrypto_lib.a' (Join-Path $androidDir 'x86_64\')
    Copy-Item 'target\i686-linux-android\release\libcrypto_lib.a' (Join-Path $androidDir 'x86\')
    
    Write-Host '? Android libraries copied' -ForegroundColor Green
    Write-Host ''
}

# Function to build Electron libraries
function Build-Electron {
    Write-Host '===========================================' -ForegroundColor Cyan
    Write-Host 'Building for Electron' -ForegroundColor Cyan
    Write-Host '===========================================' -ForegroundColor Cyan
    
    Push-Location (Join-Path $ScriptDir 'electron')
    
    npm install
    npm run build:release -- --platform
    
    Pop-Location
    
    Write-Host '? Electron libraries built' -ForegroundColor Green
    Write-Host ''
}

# Function to build Go example
function Build-GoExample {
    Write-Host '===========================================' -ForegroundColor Cyan
    Write-Host 'Building Go example' -ForegroundColor Cyan
    Write-Host '===========================================' -ForegroundColor Cyan
    
    Push-Location (Join-Path $ScriptDir 'go-example')
    
    # Build for current platform
    go build -o go-example.exe
    
    Pop-Location
    
    Write-Host '? Go example built' -ForegroundColor Green
    Write-Host ''
}

# Main build function
function Main {
    param(
        [string]$Platform = 'all'
    )
    
    switch ($Platform) {
        'android' {
            Build-Android
        }
        'electron' {
            Build-Electron
        }
        'go' {
            Build-GoExample
        }
        'all' {
            Build-Android
            Build-Electron
            Build-GoExample
        }
        default {
            Write-Host 'Usage: .\build-all.ps1 [android|electron|go|all]' -ForegroundColor Yellow
            Write-Host ''
            Write-Host 'Platforms:' -ForegroundColor Cyan
            Write-Host '  android   - Build for Android (ARM64, ARMv7, x86_64, x86)'
            Write-Host '  electron  - Build for Electron (macOS, Linux, Windows)'
            Write-Host '  go        - Build Go example'
            Write-Host '  all       - Build for all platforms (default)'
            exit 1
        }
    }
    
    Write-Host '===========================================' -ForegroundColor Cyan
    Write-Host 'Build completed successfully!' -ForegroundColor Green
    Write-Host '===========================================' -ForegroundColor Cyan
}

# Run main function
Main @args

Pop-Location
