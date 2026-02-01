# rustCrypto Android 绑定

基于 Rust 的高性能 Android 加密库，提供 Kotlin 绑定。

## 功能特性

- ✅ RSA 加密/解密
- ✅ AES-GCM 加密/解密
- ✅ ECC 密钥生成和签名
- ✅ Base58 编码/解码
- ✅ BIP32 密钥派生
- ✅ 支持 4 种架构：arm64-v8a, armeabi-v7a, x86_64, x86

## 系统要求

- Android SDK 21 (Android 5.0) 或更高
- Android NDK r21 或更高
- Kotlin 1.8 或更高
- Gradle 7.0 或更高
- Rust 1.70 或更高（仅用于编译本地库）

## 安装

### 方式一：通过 Gradle 集成（推荐）

将 AAR 文件复制到你的项目的 `libs` 目录：

```bash
cp build/outputs/aar/crypto_lib-release.aar /path/to/your/project/app/libs/
```

在 app 的 `build.gradle` 中添加：

```gradle
android {
    // ...
}

dependencies {
    implementation fileTree(dir: 'libs', include: ['*.aar'])
}
```

### 方式二：手动集成

1. 将 android 模块复制到你的项目
2. 在 settings.gradle 添加：

```gradle
include ':crypto_lib'
project(':crypto_lib').projectDir = new File(settingsDir, '../path/to/crypto_lib')
```

3. 在 app 的 build.gradle 中添加依赖：

```gradle
dependencies {
    implementation project(':crypto_lib')
}
```

## 构建

### 1. 安装 Rust targets

```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
rustup target add i686-linux-android
```

### 2. 编译 Rust 库

在项目根目录运行：

```bash
# 使用构建脚本（推荐）
cd bindings
./build-all.sh android    # Linux/macOS
.\build-all.ps1 android   # Windows

# 或手动构建
cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target x86_64-linux-android --release
cargo build --target i686-linux-android --release
```

### 3. 构建 Android AAR

```bash
cd android
./gradlew assembleRelease
```

生成的 AAR 文件位于 `build/outputs/aar/crypto_lib-release.aar`

## 快速开始

### RSA 加密/解密

```kotlin
import com.crypto.lib.CryptoLib

// 生成 RSA 密钥对
val keyPair = CryptoLib.generateRSAKeyPair(2048)
if (keyPair != null) {
    println("公钥: ${keyPair.publicKey}")
    println("私钥: ${keyPair.privateKey}")
}

// RSA 加密
val plaintext = "Hello, RSA!".toByteArray()
val encrypted = CryptoLib.rsaEncrypt(keyPair.publicKey, plaintext)
if (encrypted != null) {
    println("加密结果: ${encrypted.toHexString()}")

    // RSA 解密
    val decrypted = CryptoLib.rsaDecrypt(keyPair.privateKey, encrypted)
    if (decrypted != null) {
        println("解密结果: ${String(decrypted)}")
    }
}
```

### AES-GCM 加密/解密

```kotlin
import com.crypto.lib.CryptoLib

// 生成 AES-256 密钥
val aesKey = CryptoLib.generateAESKey()
if (aesKey != null) {
    println("AES 密钥: ${aesKey.toHexString()}")

    // AES-GCM 加密
    val plaintext = "Secret message".toByteArray()
    val encrypted = CryptoLib.aesGCMEncrypt(aesKey, plaintext)
    if (encrypted != null) {
        println("加密结果: ${encrypted.ciphertext}")
        println("Nonce: ${encrypted.nonce}")
    
        // AES-GCM 解密
        val decrypted = CryptoLib.aesGCMDecrypt(aesKey, encrypted)
        if (decrypted != null) {
            println("解密结果: ${String(decrypted)}")
        }
    }}
```

## API 文档

### CryptoLib 类

#### generateRSAKeyPair(bits: Int): KeyPair?

生成 RSA 密钥对。

**参数：**
- `bits`: 密钥长度，2048 或 4096 等

**返回：**
- `KeyPair?`: 包含 publicKey 和 privateKey 的对象，失败返回 null

#### rsaEncrypt(publicKey: String, plaintext: ByteArray): ByteArray?

使用 RSA 公钥加密数据。

**参数：**
- `publicKey`: PEM 格式的公钥
- `plaintext`: 要加密的数据

**返回：**
- `ByteArray?`: 加密后的数据，失败返回 null

#### rsaDecrypt(privateKey: String, ciphertext: ByteArray): ByteArray?

使用 RSA 私钥解密数据。

**参数：**
- `privateKey`: PEM 格式的私钥
- `ciphertext`: 要解密的数据

**返回：**
- `ByteArray?`: 解密后的数据，失败返回 null

#### generateAESKey(): ByteArray?

生成 AES-256 密钥。

**返回：**
- `ByteArray?`: 32 字节的 AES 密钥，失败返回 null

#### aesGCMEncrypt(key: ByteArray, plaintext: ByteArray): EncryptedData?

使用 AES-256-GCM 加密数据。

**参数：**
- `key`: 32 字节的 AES 密钥
- `plaintext`: 要加密的数据

**返回：**
- `EncryptedData?`: 包含 ciphertext、nonce 和 tag 的对象，失败返回 null

#### aesGCMDecrypt(key: ByteArray, encryptedData: EncryptedData): ByteArray?

使用 AES-256-GCM 解密数据。

**参数：**
- `key`: 32 字节的 AES 密钥
- `encryptedData`: 加密数据对象

**返回：**
- `ByteArray?`: 解密后的数据，失败返回 null

#### getVersion(): String

获取版本信息。

**返回：**
- `String`: 版本号字符串

### 数据类

#### KeyPair

```kotlin
data class KeyPair(
    val publicKey: String,
    val privateKey: String
)
```

#### EncryptedData

```kotlin
data class EncryptedData(
    val ciphertext: String,
    val nonce: String
)
```

## 项目结构

```
android/
├── src/main/
│   ├── cpp/
│   │   ├── CMakeLists.txt
│   │   ├── include/
│   │   │   └── crypto.h
│   │   ├── jni/
│   │   │   └── crypto_jni.cpp
│   │   └── libs/
│   │       ├── arm64-v8a/
│   │       ├── armeabi-v7a/
│   │       ├── x86_64/
│   │       └── x86/
│   └── java/com/crypto/lib/
│       └── CryptoLib.kt
├── build.gradle
└── README.md
```

## 常见问题排查

### 编译失败

如果编译失败，请检查：

1. NDK 路径在 local.properties 中配置正确
2. ANDROID_HOME 环境变量已设置
3. 已安装所有必需的 Rust targets
4. Rust 库已编译并复制到 libs 目录

### 运行时错误

如果应用运行时出现错误，请检查：

1. 设备的架构与库的架构匹配
2. ProGuard/R8 规则配置正确
3. 库文件正确加载

### JNI 崩溃

如果遇到 JNI 崩溃，请检查：

1. Java/Kotlin 方法签名与 JNI 匹配
2. C++ 代码正确处理内存管理
3. 异常正确抛出到 Java 层

## ProGuard 规则

如果使用 ProGuard 或 R8，请添加以下规则：

```proguard
-keep class com.crypto.lib.** { *; }
-keepclassmembers class com.crypto.lib.** { *; }
-dontwarn com.crypto.lib.**
```

## 示例应用

查看 `example` 目录中的示例应用，了解如何使用该库。

## 许可证

MIT License