# 跨平台加解密库

基于 Rust 实现的跨平台加解密库，支持 Go 服务端、Android、iOS、PC 和 Mac 客户端。

## 功能特性

- **RSA 加密/解密**：支持 PKCS#1 v1.5 填充
- **AES-256-CBC 加密/解密**：提供安全的对称加密
- **密钥生成**：自动生成安全的随机密钥
- **跨平台支持**：统一 API，多语言绑定

## 支持平台

- Go 服务端
- Android (Kotlin/Java + JNI)
- iOS (Swift/Objective-C)
- PC/Mac (C++)

## 编译

### 编译 Rust 库

```bash
# 编译为动态库
cargo build --release

# 编译为静态库
cargo build --release --lib
```

编译后会生成：
- `target/release/libcrypto_lib.dylib` (macOS)
- `target/release/libcrypto_lib.so` (Linux)
- `target/release/crypto_lib.dll` (Windows)
- `target/release/libcrypto_lib.a` (静态库)

### Go 绑定

```bash
cd bindings/go
go mod init crypto_example
go mod tidy
go run example.go
```

### Android 绑定

1. 将 Rust 库编译为 Android 静态库：
```bash
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
cargo build --release --target x86_64-linux-android
```

2. 在 Android 项目中配置 `build.gradle`

### iOS 绑定

1. 将 Rust 库编译为 iOS 静态库：
```bash
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
```

2. 在 Xcode 项目中添加静态库和头文件

### C++ 绑定

```bash
cd bindings/cpp
g++ -std=c++17 -I../../include -L../../target/release -lcrypto_lib -lssl -lcrypto -o example example.cpp CryptoLib.cpp
./example
```

## API 使用示例

### Go

```go
// 生成 RSA 密钥对
keypair, err := crypto.GenerateRSAKeyPair(2048)

// RSA 加密
encrypted, err := crypto.RSAEncrypt(keypair.PublicKey, []byte("Hello"))

// RSA 解密
decrypted, err := crypto.RSADecrypt(keypair.PrivateKey, encrypted)

// 生成 AES 密钥
aesKey, err := crypto.GenerateAESKey()

// AES-CBC 加密
encryptedData, err := crypto.AESGCMEncrypt(aesKey, []byte("Hello"))

// AES-CBC 解密
decrypted, err := crypto.AESGCMDecrypt(aesKey, encryptedData)
```

### Android (Kotlin)

```kotlin
// 生成 RSA 密钥对
val keyPair = CryptoLib.generateRSAKeyPair(2048)

// RSA 加密
val encrypted = CryptoLib.rsaEncrypt(keyPair.publicKey, plaintext)

// RSA 解密
val decrypted = CryptoLib.rsaDecrypt(keyPair.privateKey, encrypted)

// 生成 AES 密钥
val aesKey = CryptoLib.generateAESKey()

// AES-CBC 加密
val encryptedData = CryptoLib.aesGCMEncrypt(aesKey, plaintext)

// AES-CBC 解密
val decrypted = CryptoLib.aesGCMDecrypt(aesKey, encryptedData)
```

### iOS (Swift)

```swift
// 生成 RSA 密钥对
let keyPair = CryptoLib.generateRSAKeyPair(bits: 2048)

// RSA 加密
let encrypted = CryptoLib.rsaEncrypt(publicKey: keyPair.publicKey, plaintext: plaintext)

// RSA 解密
let decrypted = CryptoLib.rsaDecrypt(privateKey: keyPair.privateKey, ciphertext: encrypted)

// 生成 AES 密钥
let aesKey = CryptoLib.generateAESKey()

// AES-CBC 加密
let encryptedData = CryptoLib.aesGCMEncrypt(key: aesKey, plaintext: plaintext)

// AES-CBC 解密
let decrypted = CryptoLib.aesGCMDecrypt(key: aesKey, encryptedData: encryptedData)
```

### C++

```cpp
// 生成 RSA 密钥对
auto keyPair = crypto::CryptoLib::generateRSAKeyPair(2048);

// RSA 加密
auto encrypted = crypto::CryptoLib::rsaEncrypt(keyPair->getPublicKey(), plaintext);

// RSA 解密
auto decrypted = crypto::CryptoLib::rsaDecrypt(keyPair->getPrivateKey(), encrypted->toVector());

// 生成 AES 密钥
auto aesKey = crypto::CryptoLib::generateAESKey();

// AES-CBC 加密
auto encryptedData = crypto::CryptoLib::aesGCMEncrypt(aesKey->toVector(), plaintext);

// AES-CBC 解密
auto decrypted = crypto::CryptoLib::aesGCMDecrypt(aesKey->toVector(), *encryptedData);
```

## 项目结构

```
rsa/
├── src/
│   ├── lib.rs           # 库入口
│   ├── crypto.rs        # 核心加解密实现
│   └── ffi.rs           # C FFI 接口
├── include/
│   └── crypto.h         # 自动生成的 C 头文件
├── bindings/
│   ├── go/              # Go 语言绑定
│   ├── android/         # Android 绑定
│   ├── ios/             # iOS 绑定
│   └── cpp/             # C++ 绑定
├── Cargo.toml
├── build.rs             # 构建脚本
└── README.md
```

## 安全注意事项

1. 私钥必须妥善保管，不要泄露
2. 在生产环境中使用前，请进行充分的安全审计
3. 建议使用硬件安全模块 (HSM) 存储敏感密钥
4. 定期更新依赖库以获取安全补丁

## 许可证

MIT License