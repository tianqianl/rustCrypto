# rustCrypto 绑定目录

本目录包含 rustCrypto 的多平台绑定和示例代码。

## 目录结构

```
bindings/
├── go-example/        # Go 语言绑定和示例
├── android/           # Android (Kotlin + JNI) 绑定
├── ios/               # iOS (Swift) 绑定
├── electron/          # Electron (N-API) 绑定
├── cpp/               # C++ 绑定
├── build-all.sh       # Linux/macOS 构建脚本
├── build-all.ps1      # Windows 构建脚本
└── README.md          # 本文件
```

## 快速开始

### 1. 编译 Rust 项目

首先需要为特定平台编译 Rust 项目库：

```bash
# 在项目根目录
cargo build --release
```

### 2. 构建特定平台绑定

选择你需要的平台绑定：

#### Go

```bash
cd go-example
go run example.go
```

#### Android

```bash
# 使用构建脚本（推荐）
./build-all.sh android  # Linux/macOS
.\build-all.ps1 android  # Windows

# 或手动构建
cd android
./gradlew assembleRelease
```

#### iOS

```bash
# 使用构建脚本（需要 macOS）
./build-all.sh ios

# 或使用 CocoaPods 安装
cd ios
pod install
```

#### Electron

```bash
cd electron
npm install
npm run build
```

## 构建脚本

提供了便捷的多平台构建脚本：

### build-all.sh (Linux/macOS)

```bash
# 构建所有平台
./build-all.sh all

# 构建特定平台
./build-all.sh android
./build-all.sh ios
./build-all.sh electron
./build-all.sh go
```

### build-all.ps1 (Windows)

```powershell
# 构建所有平台
.\build-all.ps1 all

# 构建特定平台
.\build-all.ps1 android
.\build-all.ps1 electron
.\build-all.ps1 go
```

## 平台特定文档

每个平台都有详细的文档和示例：

- [Go 绑定](go-example/README.md) - 包含 Go API 文档和使用示例
- [Android 绑定](android/README.md) - Android AAR 构建指南
- [iOS 绑定](ios/README.md) - iOS Framework 和 Swift 集成
- [Electron 绑定](electron/README.md) - N-API 模块和 JavaScript API

## 前置要求

### 通用

- Rust 1.70+
- cargo

### Go 绑定

- Go 1.21+

### Android 绑定

- Android NDK r21+
- Android SDK 21+
- Gradle 7.0+
- Java 8+

### iOS 绑定

- Xcode 14+
- iOS SDK 12.0+
- CocoaPods

### Electron 绑定

- Node.js 16+
- npm 或 yarn

## 常见问题排查

### Rust 编译问题

如果 Rust 编译失败，请确保：

1. 已安装最新版本的 Rust：`rustup update`
2. 已安装所需的 target：`rustup target add <target>`
3. 已安装所需的系统依赖

### Android 编译失败

如果 Android 编译失败，请检查：

1. NDK 路径在 local.properties 中配置正确
2. ANDROID_HOME 环境变量已设置
3. 已安装所有必需的 Rust targets

### iOS 编译失败

如果 iOS 编译失败，请检查：

1. 在 macOS 上运行
2. Xcode 命令行工具已安装：`xcode-select --install`
3. 已安装 iOS targets

## 贡献

欢迎为任何平台绑定做出贡献！请参考相应平台的 README 了解详情。

## 许可证

MIT License