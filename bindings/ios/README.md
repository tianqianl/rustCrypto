# rustCrypto iOS Framework

基于 Rust 的高性能 iOS 加密库，提供 Swift 绑定。

## 功能特性

- ✅ RSA 加密/解密
- ✅ AES-GCM 加密/解密
- ✅ ECC 密钥生成和签名
- ✅ Base58 编码/解码
- ✅ BIP32 密钥派生
- ✅ 支持 iOS 12.0+
- ✅ 支持 ARM64 和 x86_64 架构

## 系统要求

- iOS 12.0 或更高
- Xcode 14.0 或更高
- Swift 5.0 或更高
- Rust 1.70 或更高（仅用于编译本地库）

## 安装

### 方式一：CocoaPods（推荐）

在 Podfile 添加：

```ruby
pod 'crypto_lib', :git => 'https://github.com/tianqianl/rustCrypto.git'
```

然后运行：

```bash
pod install
```

### 方式二：手动集成 XCFramework

1. 下载预编译的 XCFramework
2. 在 Xcode 中，选择你的项目 target
3. 点击 "General" 标签
4. 找到 "Frameworks, Libraries, and Embedded Content"
5. 点击 "+" 按钮，选择 XCFramework
6. 选择 `crypto_lib.xcframework` 文件
7. 确保 "Embed & Sign" 选项已选中

### 方式三：从源码构建

#### 1. 安装 Rust targets

```bash
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add x86_64-apple-ios
```

#### 2. 编译 Rust 库

在项目根目录运行：

```bash
cd bindings
./build-all.sh ios
```

#### 3. 创建 XCFramework

```bash
cd ios
xcodebuild -create-xcframework \
  -library ../../target/aarch64-apple-ios/release/libcrypto_lib.a \
  -headers ../../include \
  -library ../../target/aarch64-apple-ios-sim/release/libcrypto_lib.a \
  -headers ../../include \
  -library ../../target/x86_64-apple-ios/release/libcrypto_lib.a \
  -headers ../../include \
  -output Frameworks/crypto_lib.xcframework
```

## 快速开始

### RSA 加密/解密

```swift
import CryptoLib

// 生成 RSA 密钥对
if let keyPair = CryptoLib.generateRSAKeyPair(bits: 2048) {
    print("公钥: \(keyPair.publicKey)")
    print("私钥: \(keyPair.privateKey)")

    // RSA 加密
    let plaintext = "Hello, RSA!".data(using: .utf8)!
    if let encrypted = CryptoLib.rsaEncrypt(publicKey: keyPair.publicKey, plaintext: plaintext) {
        print("加密结果: \(encrypted.base64EncodedString())")

        // RSA 解密
        if let decrypted = CryptoLib.rsaDecrypt(privateKey: keyPair.privateKey, ciphertext: encrypted) {
            let decryptedString = String(data: decrypted, encoding: .utf8)
            print("解密结果: \(decryptedString ?? "")")
        }
    }
}
```

### AES-GCM 加密/解密

```swift
import CryptoLib

// 生成 AES-256 密钥
if let aesKey = CryptoLib.generateAESKey() {
    print("AES 密钥: \(aesKey.base64EncodedString())")

    // AES-GCM 加密
    let plaintext = "Secret message".data(using: .utf8)!
    if let encrypted = CryptoLib.aesGCMEncrypt(key: aesKey, plaintext: plaintext) {
        print("加密结果: \(encrypted.ciphertext)")
        print("Nonce: \(encrypted.nonce)")
    
        // AES-GCM 解密
        if let decrypted = CryptoLib.aesGCMDecrypt(key: aesKey, encryptedData: encrypted) {
            let decryptedString = String(data: decrypted, encoding: .utf8)
            print("解密结果: \(decryptedString ?? "")")
        }
    }}
```

### ECC 加密

```swift
import CryptoLib

// 生成 ECC 密钥对
if let keyPair = CryptoLib.generateECCKey() {
    print("公钥: \(keyPair.publicKey)")
    print("私钥: \(keyPair.privateKey)")

    // 签名
    let message = "Hello, ECC!".data(using: .utf8)!
    if let signature = CryptoLib.eccSign(message: message, privateKey: keyPair.privateKey) {
        print("签名: \(signature.base64EncodedString())")

        // 验证
        let isValid = CryptoLib.eccVerify(message: message, signature: signature, publicKey: keyPair.publicKey)
        print("验证结果: \(isValid)")

        // 获取地址
        if let address = CryptoLib.eccGetAddress(publicKey: keyPair.publicKey) {
            print("地址: \(address.hexEncodedString())")
        }
    }
}
```

## API 文档

### CryptoLib 类

#### RSA 加密

```swift
static func generateRSAKeyPair(bits: Int) -> KeyPair?
```

生成 RSA 密钥对。

**参数：**
- `bits`: 密钥长度，2048 或 4096 等

**返回：**
- `KeyPair?`: 包含 publicKey 和 privateKey 的对象，失败返回 nil

```swift
static func rsaEncrypt(publicKey: String, plaintext: Data) -> Data?
```

使用 RSA 公钥加密数据。

**参数：**
- `publicKey`: PEM 格式的公钥
- `plaintext`: 要加密的数据

**返回：**
- `Data?`: 加密后的数据，失败返回 nil

```swift
static func rsaDecrypt(privateKey: String, ciphertext: Data) -> Data?
```

使用 RSA 私钥解密数据。

**参数：**
- `privateKey`: PEM 格式的私钥
- `ciphertext`: 要解密的数据

**返回：**
- `Data?`: 解密后的数据，失败返回 nil

#### AES 加密

```swift
static func generateAESKey() -> Data?
```

生成 AES-256 密钥。

**返回：**
- `Data?`: 32 字节的 AES 密钥，失败返回 nil

```swift
static func aesGCMEncrypt(key: Data, plaintext: Data) -> EncryptedData?
```

使用 AES-256-GCM 加密数据。

**参数：**
- `key`: 32 字节的 AES 密钥
- `plaintext`: 要加密的数据

**返回：**
- `EncryptedData?`: 包含 ciphertext、nonce 和 tag 的对象，失败返回 nil

```swift
static func aesGCMDecrypt(key: Data, encryptedData: EncryptedData) -> Data?
```

使用 AES-256-GCM 解密数据。

**参数：**
- `key`: 32 字节的 AES 密钥
- `encryptedData`: 加密数据对象

**返回：**
- `Data?`: 解密后的数据，失败返回 nil

#### ECC 加密

```swift
static func generateECCKey() -> KeyPair?
```

生成 ECC 密钥对。

**返回：**
- `KeyPair?`: 包含 publicKey 和 privateKey 的对象，失败返回 nil

```swift
static func eccSign(message: Data, privateKey: String) -> Data?
```

使用私钥对消息进行签名。

**参数：**
- `message`: 要签名的消息
- `privateKey`: Base58 格式的私钥

**返回：**
- `Data?`: DER 格式的签名，失败返回 nil

```swift
static func eccVerify(message: Data, signature: Data, publicKey: String) -> Bool
```

使用公钥验证签名。

**参数：**
- `message`: 原始消息
- `signature`: DER 格式的签名
- `publicKey`: Base58 格式的公钥

**返回：**
- `Bool`: 签名是否有效

```swift
static func eccGetAddress(publicKey: String) -> Data?
```

从公钥生成地址（以太坊格式）。

**参数：**
- `publicKey`: Base58 格式的公钥

**返回：**
- `Data?`: 20 字节的地址，失败返回 nil

#### Base58 编码

```swift
static func base58Encode(data: Data) -> String
```

Base58 编码。

**参数：**
- `data`: 要编码的数据

**返回：**
- `String`: Base58 编码后的字符串

```swift
static func base58Decode(encoded: String) -> Data?
```

Base58 解码。

**参数：**
- `encoded`: Base58 编码的字符串

**返回：**
- `Data?`: 解码后的数据，失败返回 nil

#### 版本信息

```swift
static func getVersion() -> String
```

获取版本信息。

**返回：**
- `String`: 版本号字符串

### 数据结构

#### KeyPair

```swift
public struct KeyPair {
    public let publicKey: String
    public let privateKey: String
}
```

#### EncryptedData

```swift
public struct EncryptedData {
    public let ciphertext: String
    public let nonce: String
}
```

## 常见问题排查

### 编译失败

如果编译失败，请检查：

1. Xcode 命令行工具已安装：`xcode-select --install`
2. 已安装所有必需的 Rust targets
3. Rust 库已成功编译
4. XCFramework 已成功创建

### 运行时错误

如果运行时出现错误，请检查：

1. Framework 正确添加到项目
2. "Embed & Sign" 选项已选中
3. 密钥格式正确
4. 数据格式有效

### 模拟器兼容性

如果模拟器上出现问题，请检查：

1. 确保使用正确的架构（ARM64 或 x86_64）
2. XCFramework 包含模拟器支持
3. 清理项目文件夹（Cmd + Shift + K）

## 示例应用

查看 `example` 目录中的示例应用，了解如何使用该库。

## 许可证

MIT License