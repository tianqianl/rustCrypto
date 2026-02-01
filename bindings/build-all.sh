#!/bin/bash

# Build script for rustCrypto library on all platforms
# This script builds the Rust library for all target platforms

set -e

echo '==========================================='
echo 'Building rustCrypto for all platforms'
echo '==========================================='
echo ''

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Function to build for a specific target
build_target() {
    local target=$1
    local name=$2
    
    echo "Building for $name ($target)..."
    
    # Check if target is installed
    if ! rustup target list --installed | grep -q "^$target "; then
        echo "Installing target $target..."
        rustup target add "$target"
    fi
    
    # Build the library
    cargo build --target "$target" --release
    
    echo "? Built for $name"
    echo ''
}

# Function to build Android libraries
build_android() {
    echo '==========================================='
    echo 'Building for Android'
    echo '==========================================='
    
    local targets=(
        "aarch64-linux-android:ARM64"
        "armv7-linux-androideabi:ARMv7"
        "x86_64-linux-android:x86_64"
        "i686-linux-android:x86"
    )
    
    for target_info in "${targets[@]}"; do
        IFS=':' read -r target arch <<< "$target_info"
        build_target "$target" "Android $arch"
    done
    
    # Copy libraries to Android project
    echo 'Copying libraries to Android project...'
    
    local android_dir="$SCRIPT_DIR/android/src/main/cpp/libs"
    mkdir -p "$android_dir"/{arm64-v8a,armeabi-v7a,x86_64,x86}
    
    cp "target/aarch64-linux-android/release/libcrypto_lib.a" "$android_dir/arm64-v8a/"
    cp "target/armv7-linux-androideabi/release/libcrypto_lib.a" "$android_dir/armeabi-v7a/"
    cp "target/x86_64-linux-android/release/libcrypto_lib.a" "$android_dir/x86_64/"
    cp "target/i686-linux-android/release/libcrypto_lib.a" "$android_dir/x86/"
    
    echo '? Android libraries copied'
    echo ''
}

# Function to build iOS libraries
build_ios() {
    echo '==========================================='
    echo 'Building for iOS'
    echo '==========================================='
    
    local targets=(
        "aarch64-apple-ios:iOS Device (ARM64)"
        "aarch64-apple-ios-sim:iOS Simulator (ARM64)"
        "x86_64-apple-ios:iOS Simulator (x86_64)"
    )
    
    for target_info in "${targets[@]}"; do
        IFS=':' read -r target arch <<< "$target_info"
        build_target "$target" "$arch"
    done
    
    # Create XCFramework
    echo 'Creating XCFramework...'
    
    local ios_dir="$SCRIPT_DIR/ios/Frameworks"
    mkdir -p "$ios_dir"
    
    xcodebuild -create-xcframework \\
        -library target/aarch64-apple-ios/release/libcrypto_lib.a \\
        -headers include \\
        -library target/aarch64-apple-ios-sim/release/libcrypto_lib.a \\
        -headers include \\
        -library target/x86_64-apple-ios/release/libcrypto_lib.a \\
        -headers include \\
        -output "$ios_dir/crypto_lib.xcframework"
    
    echo '? XCFramework created'
    echo ''
}

# Function to build Electron libraries
build_electron() {
    echo '==========================================='
    echo 'Building for Electron'
    echo '==========================================='
    
    cd "$SCRIPT_DIR/electron"
    
    npm install
    npm run build:release -- --platform
    
    cd "$PROJECT_ROOT"
    
    echo '? Electron libraries built'
    echo ''
}

# Function to build Go example
build_go_example() {
    echo '==========================================='
    echo 'Building Go example'
    echo '==========================================='
    
    cd "$SCRIPT_DIR/go-example"
    
    # Build for current platform
    go build -o go-example
    
    cd "$PROJECT_ROOT"
    
    echo '? Go example built'
    echo ''
}

# Main build function
main() {
    local platform=${1:-all}
    
    case $platform in
        android)
            build_android
            ;;
        ios)
            build_ios
            ;;
        electron)
            build_electron
            ;;
        go)
            build_go_example
            ;;
        all)
            build_android
            build_ios
            build_electron
            build_go_example
            ;;
        *)
            echo 'Usage: $0 [android|ios|electron|go|all]'
            echo ''
            echo 'Platforms:'
            echo '  android   - Build for Android (ARM64, ARMv7, x86_64, x86)'
            echo '  ios       - Build for iOS (Device ARM64, Simulator ARM64/x86_64)'
            echo '  electron  - Build for Electron (macOS, Linux, Windows)'
            echo '  go        - Build Go example'
            echo '  all       - Build for all platforms (default)'
            exit 1
            ;;
    esac
    
    echo '==========================================='
    echo 'Build completed successfully!'
    echo '==========================================='
}

# Run main function
main "$@"
