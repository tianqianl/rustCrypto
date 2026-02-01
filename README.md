# rustCrypto - 跨平台加密库

一个用 Rust 编写的高性能加密库，支持多平台绑定。

## 功能特性

- **RSA 加密/解密** - 支持多种密钥长度（2048、4096 位等）
- **AES-GCM 加密/解密** - 经过认证的 AES-256-GCM 加密
- **ECC 加密** - secp256k1 曲线，支持密钥生成、签名和验证
- **Base58 编码/解码** - 专为比特币优化的 Base58 编码
- **BIP32 密钥派生** - 层级确定性密钥派生

## 支持的平台

| 平台 | 状态 | 架构 | 绑定方式 |
|------|------|------|----------|
| **Windows** | ✅ 完全支持 | x86_64 | C FFI + Go |
| **macOS** | ✅ 完全支持 | x86_64, ARM64 | C FFI + Go |
| **Linux** | ✅ 完全支持 | x86_64 | C FFI + Go |
| **Android** | ✅ 完全支持 | ARM64, ARMv7, x86_64, x86 | Kotlin + JNI |
| **iOS** | ✅ 完全支持 | ARM64, ARM64-sim, x86_64 | Swift |
| **Electron** | ✅ 完全支持 | macOS, Linux, Windows | N-API |

## 项目结构

```
rustCrypto/
├── src/                    # Rust 源代码
│   ├── lib.rs             # 库入口
│   ├── ffi.rs             # C FFI 层
│   ├── crypto.rs          # RSA 和 AES 实现
│   └── ecc.rs             # ECC 实现
├── include/               # 生成的 C 头文件
│   └── crypto.h           # C API 定义
├── bindings/              # 平台特定绑定
│   ├── go-example/        # Go 绑定和示例
│   ├── android/           # Android (Kotlin + JNI)
│   ├── ios/               # iOS (Swift)
│   ├── electron/          # Electron (N-API)
│   └── cpp/               # C++ 绑定
├── Cargo.toml             # Rust 项目配置
└── build.rs               # 头文件生成脚本
```

## 快速开始

### Go

```bash
cd bindings/go-example
go run example.go
```

### Android

```bash
# 为所有 Android 架构编译 Rust 库
cd bindings
./build-all.sh android  # Linux/macOS
.\build-all.ps1 android  # Windows

# 构建 Android AAR
cd android
./gradlew assembleRelease
```

### iOS

```bash
# 为 iOS 编译 Rust 库
cd bindings
./build-all.sh ios  # Linux/macOS

# 构建 XCFramework（需要 macOS）
cd ios
# 使用 Frameworks/ 中预编译的 XCFramework
```

### Electron

```bash
cd bindings/electron
npm install
npm run build
```

## 构建

### 前置要求

- Rust 1.70 或更高版本
- Android: Android NDK r21+, Android SDK 21+
- iOS: Xcode 14+, iOS SDK 12.0+
- Electron: Node.js 16+, npm 或 yarn
- Go: Go 1.21+

### 构建所有平台

#### Linux/macOS

```bash
cd bindings
chmod +x build-all.sh
./build-all.sh all
```

#### Windows

```powershell
cd bindings
.\build-all.ps1 all
```

### 构建特定平台

```bash
# Linux/macOS
./build-all.sh android
./build-all.sh ios
./build-all.sh electron
./build-all.sh go

# Windows
.\build-all.ps1 android
.\build-all.ps1 electron
.\build-all.ps1 go
```

## 平台特定文档

- [Go](bindings/go-example/README.md) - Go 绑定和使用示例
- [Android](bindings/android/README.md) - Android AAR 构建 Kotlin API
- [iOS](bindings/ios/README.md) - iOS Framework 和 Swift API
- [Electron](bindings/electron/README.md) - Electron N-API 模块和 JavaScript API

## API 参考

### C FFI（核心 API）

项目提供 C 兼容的 FFI 接口：

```c
// RSA 密钥生成
CKeyPair* crypto_generate_rsa_keypair(int bits);

// RSA 加密/解密
CByteArray* crypto_rsa_encrypt(const char* public_key, const uint8_t* plaintext, size_t len, size_t* out_len);
CByteArray* crypto_rsa_decrypt(const char* private_key, const uint8_t* ciphertext, size_t len, size_t* out_len);

// AES-GCM 加密/解密
CEncryptedData* crypto_aes_gcm_encrypt(const uint8_t* key, size_t key_len, const uint8_t* plaintext, size_t plaintext_len);
CByteArray* crypto_aes_gcm_decrypt(const uint8_t* key, size_t key_len, const CEncryptedData* encrypted, size_t* out_len);

// ECC 加密
CKeyPair* crypto_ecc_generate_key(void);
CByteArray* crypto_ecc_sign(const uint8_t* message, size_t message_len, const char* private_key, size_t* out_len);
int crypto_ecc_verify(const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len, const char* public_key);
CByteArray* crypto_ecc_get_address(const char* public_key, size_t* out_len);

// Base58 编码/解码
char* crypto_ecc_base58_encode(const uint8_t* data, size_t data_len);
CByteArray* crypto_ecc_base58_decode(const char* encoded, size_t* out_len);

// BIP32 密钥派生
CKeyPair* crypto_ecc_get_key_by_seed_and_path(const char* seed, const char* path);

// 内存管理
void crypto_free_keypair(CKeyPair* keypair);
void crypto_free_byte_array(CByteArray* array);
void crypto_free_encrypted_data(CEncryptedData* data);

// 版本信息
const char* crypto_get_version(void);
```

## 安全注意事项

- 所有加密操作都使用经过验证的加密原语
- 随机数生成使用操作系统的 CSPRNG
- 密钥绝不会被记录或暴露在内存中
- 使用安全的内存管理

## 测试

```bash
# 运行 Rust 测试
cargo test

# 运行 Go 测试
cd bindings/go-example
go test ./...

# 运行 Electron 测试
cd bindings/electron
npm test
```

## 贡献

欢迎贡献！请遵循以下标准

1. Fork 本仓库
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 确保所有测试通过
6. 提交 Pull Request

## 许可证

MIT License - 查看 LICENSE 文件

## 致谢

- [RustCrypto](https://github.com/RustCrypto) - 加密算法实现
- [N-API](https://nodejs.org/api/n-api.html) - Node.js 原生 API
- [cbindgen](https://github.com/eqrion/cbindgen) - C 头文件生成

## 联系方式

- GitHub: https://github.com/tianqianl/rustCrypto
- Issues: https://github.com/tianqianl/rustCrypto/issues