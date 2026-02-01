# rustCrypto Go 绑定

rustCrypto 加密库的 Go 语言绑定，提供多种加密算法的封装

## 功能特性

- ✅ RSA 加密/解密
- ✅ AES-GCM 加密/解密
- ✅ ECC 密钥生成和签名
- ✅ Base58 编码/解码
- ✅ BIP32 密钥派生
- ✅ 跨平台支持：Windows、macOS、Linux

## 安装

### 前置要求

- Go 1.21 或更高版本
- Rust 1.70 或更高版本（仅用于编译本地库）

### 编译本地库

在 Windows 上：

```bash
# 编译 Rust 静态库
cd ../..
cargo build --release

# 复制库文件到 crypto 目录
copy target\release\libcrypto_lib.a bindings\go-example\crypto\
copy include\crypto.h bindings\go-example\crypto\
```

在 macOS/Linux 上：

```bash
# 编译 Rust 静态库
cd ../..
cargo build --release

# 复制库文件到 crypto 目录
cp target/release/libcrypto_lib.a bindings/go-example/crypto/
cp include/crypto.h bindings/go-example/crypto/
```

## 快速开始

### RSA 加密/解密

```go
package main

import (
    "fmt"
    "crypto"
)

func main() {
    // 生成 RSA 密钥对
    keyPair, err := crypto.GenerateRSAKeyPair(2048)
    if err != nil {
        panic(err)
    }

    fmt.Printf("公钥: %s\n", keyPair.PublicKey)
    fmt.Printf("私钥: %s\n", keyPair.PrivateKey)

    // RSA 加密
    plaintext := []byte("Hello, RSA!")
    encrypted, err := crypto.RSAEncrypt(keyPair.PublicKey, plaintext)
    if err != nil {
        panic(err)
    }

    fmt.Printf("加密结果: %x\n", encrypted)

    // RSA 解密
    decrypted, err := crypto.RSADecrypt(keyPair.PrivateKey, encrypted)
    if err != nil {
        panic(err)
    }

    fmt.Printf("解密结果: %s\n", decrypted)
}
```

### AES-GCM 加密/解密

```go
package main

import (
    "fmt"
    "crypto"
)

func main() {
    // 生成 AES-256 密钥
    key, err := crypto.GenerateAESKey()
    if err != nil {
        panic(err)
    }

    fmt.Printf("AES 密钥: %x\n", key)

    // AES-GCM 加密
    plaintext := []byte("Secret message")
    encrypted, err := crypto.AESGCMEncrypt(key, plaintext)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("密文: %s\n", encrypted.Ciphertext)
    fmt.Printf("Nonce: %s\n", encrypted.Nonce)
    
    // AES-GCM 解密
    decrypted, err := crypto.AESGCMDecrypt(key, encrypted)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("解密结果: %s\n", decrypted)}
```

### ECC 加密

```go
package main

import (
    "fmt"
    "ecc"
)

func main() {
    // 生成 ECC 密钥对
    keyPair, err := ecc.GenerateKey()
    if err != nil {
        panic(err)
    }

    fmt.Printf("公钥: %s\n", keyPair.PublicKey)
    fmt.Printf("私钥: %s\n", keyPair.PrivateKey)

    // 签名
    message := []byte("Hello, ECC!")
    signature, err := ecc.Sign(message, keyPair.PrivateKey)
    if err != nil {
        panic(err)
    }

    fmt.Printf("签名: %x\n", signature)

    // 验证
    isValid, err := ecc.Verify(message, signature, keyPair.PublicKey)
    if err != nil {
        panic(err)
    }

    fmt.Printf("验证结果: %v\n", isValid)

    // 获取地址
    address, err := ecc.GetAddress(keyPair.PublicKey)
    if err != nil {
        panic(err)
    }

    fmt.Printf("地址: %x\n", address)
}
```

### BIP32 密钥派生

```go
package main

import (
    "fmt"
    "ecc"
)

func main() {
    // 通过助记词和路径派生密钥
    seed := "my_seed_phrase_12345"
    path := "m/44'/60'/0'/0/0"

    keyPair, err := ecc.GetKeyBySeedAndPath(seed, path)
    if err != nil {
        panic(err)
    }

    fmt.Printf("派生密钥 - 公钥: %s\n", keyPair.PublicKey)
    fmt.Printf("派生密钥 - 私钥: %s\n", keyPair.PrivateKey)
}
```

### Base58 编码/解码

```go
package main

import (
    "fmt"
    "ecc"
)

func main() {
    // Base58 编码
    data := []byte("Hello, Base58!")
    encoded := ecc.Base58Encode(data)
    fmt.Printf("编码结果: %s\n", encoded)

    // Base58 解码
    decoded, err := ecc.Base58Decode(encoded)
    if err != nil {
        panic(err)
    }

    fmt.Printf("解码结果: %s\n", decoded)
}
```

## API 文档

### crypto 包

#### GenerateRSAKeyPair(bits int) (*KeyPair, error)

生成 RSA 密钥对。

**参数：**
- `bits`: 密钥长度，2048 或 4096 等

**返回：**
- `*KeyPair`: 包含公钥和私钥
- `error`: 错误信息

#### RSAEncrypt(publicKey string, plaintext []byte) ([]byte, error)

使用 RSA 公钥加密数据。

**参数：**
- `publicKey`: PEM 格式的公钥
- `plaintext`: 要加密的数据

**返回：**
- `[]byte`: 加密后的数据
- `error`: 错误信息

#### RSADecrypt(privateKey string, ciphertext []byte) ([]byte, error)

使用 RSA 私钥解密数据。

**参数：**
- `privateKey`: PEM 格式的私钥
- `ciphertext`: 要解密的数据

**返回：**
- `[]byte`: 解密后的数据
- `error`: 错误信息

#### GenerateAESKey() ([]byte, error)

生成 AES-256 密钥。

**返回：**
- `[]byte`: 32 字节的 AES 密钥
- `error`: 错误信息

#### AESGCMEncrypt(key []byte, plaintext []byte) (*EncryptedData, error)

使用 AES-256-GCM 加密数据。

**参数：**
- `key`: 32 字节的 AES 密钥
- `plaintext`: 要加密的数据

**返回：**
- `*EncryptedData`: 包含密文和 nonce
- `error`: 错误信息

#### AESGCMDecrypt(key []byte, encrypted *EncryptedData) ([]byte, error)

使用 AES-256-GCM 解密数据。

**参数：**
- `key`: 32 字节的 AES 密钥
- `encrypted`: 加密数据对象

**返回：**
- `[]byte`: 解密后的数据
- `error`: 错误信息

### ecc 包

#### GenerateKey() (*KeyPair, error)

生成 ECC 密钥对（secp256k1 曲线）。

**返回：**
- `*KeyPair`: 包含公钥和私钥
- `error`: 错误信息

#### Sign(message []byte, privateKey string) ([]byte, error)

使用私钥对消息进行签名。

**参数：**
- `message`: 要签名的消息
- `privateKey`: Base58 格式的私钥

**返回：**
- `[]byte`: DER 格式的签名
- `error`: 错误信息

#### Verify(message []byte, signature []byte, publicKey string) (bool, error)

使用公钥验证签名。

**参数：**
- `message`: 原始消息
- `signature`: DER 格式的签名
- `publicKey`: Base58 格式的公钥

**返回：**
- `bool`: 签名是否有效
- `error`: 错误信息

#### GetAddress(publicKey string) ([]byte, error)

从公钥生成地址（以太坊格式）。

**参数：**
- `publicKey`: Base58 格式的公钥

**返回：**
- `[]byte`: 20 字节的地址
- `error`: 错误信息

#### Base58Encode(data []byte) string

Base58 编码。

**参数：**
- `data`: 要编码的数据

**返回：**
- `string`: Base58 编码后的字符串

#### Base58Decode(encoded string) ([]byte, error)

Base58 解码。

**参数：**
- `encoded`: Base58 编码的字符串

**返回：**
- `[]byte`: 解码后的数据
- `error`: 错误信息

#### GetKeyBySeedAndPath(seed string, path string) (*KeyPair, error)

通过助记词和派生路径生成密钥（BIP32 标准）。

**参数：**
- `seed`: 助记词字符串
- `path`: 派生路径，如 "m/44'/60'/0'/0/0"

**返回：**
- `*KeyPair`: 包含公钥和私钥
- `error`: 错误信息

## 运行示例

```bash
# 运行示例程序
go run example.go

# 运行所有测试
go test ./...
```

## 编译可执行文件

```bash
# 编译当前平台
go build -o go-example

# 编译特定平台
GOOS=linux GOARCH=amd64 go build -o go-example-linux
GOOS=windows GOARCH=amd64 go build -o go-example.exe
GOOS=darwin GOARCH=amd64 go build -o go-example-mac
```

## 常见问题排查

### 编译问题

如果编译时遇到错误，请确保：

1. Rust 库已正确编译并复制到 crypto 目录
2. crypto.h 头文件存在于 crypto 目录
3. CGO 配置正确（检查 crypto.go 中的 #cgo 指令）

### 链接错误

如果遇到链接错误或缺少符号，请尝试：

1. 检查平台特定的链接标志（crypto.go 中的 LDFLAGS）
2. 确保系统已安装必要的依赖（Windows: bcrypt, ndll 等）

### 运行时错误

如果程序运行时出现错误，请检查：

1. 库文件路径是否正确
2. 密钥格式是否正确
3. 输入数据是否有效

## 许可证

MIT License