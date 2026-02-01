# rustCrypto Electron 模块

基于 Rust 的高性能 Electron 加密库，提供 N-API 绑定。

## 功能特性

- ✅ RSA 加密/解密
- ✅ AES-GCM 加密/解密
- ✅ ECC 密钥生成和签名
- ✅ Base58 编码/解码
- ✅ BIP32 密钥派生
- ✅ 跨平台支持：Windows、macOS、Linux
- ✅ 低复杂数优化

## 系统要求

- Node.js 16 或更高
- npm 或 yarn
- Electron 11 或更高
- Rust 1.70 或更高（仅用于编译本地库）

## 安装

### 方式一：npm 安装

```bash
npm install rust-crypto-electron
```

使用 yarn：

```bash
yarn add rust-crypto-electron
```

### 方式二：从源码构建

```bash
# 克隆仓库
git clone https://github.com/tianqianl/rustCrypto.git
cd rustCrypto/bindings/electron

# 安装依赖
npm install

# 构建
npm run build
```

## 快速开始

### 基本使用

```javascript
const {
  generateRSAKeyPair,
  rsaEncrypt,
  rsaDecrypt,
  generateAESKey,
  aesEncrypt,
  aesDecrypt
} = require('rust-crypto-electron');

// RSA 加密/解密
const keyPair = generateRSAKeyPair(2048);
console.log('公钥:', keyPair.public_key);
console.log('私钥:', keyPair.private_key);

const plaintext = 'Hello, World!';
const encrypted = rsaEncrypt(keyPair.public_key, plaintext);
console.log('加密结果:', encrypted);

const decrypted = rsaDecrypt(keyPair.private_key, encrypted);
console.log('解密结果:', decrypted);

// AES-GCM 加密/解密
const aesKey = generateAESKey();
console.log('AES 密钥:', aesKey);

const encryptedData = aesEncrypt(aesKey, 'Secret message');
console.log('加密结果:', encryptedData);

const decryptedData = aesDecrypt(aesKey, encryptedData);
console.log('解密结果:', decryptedData);
```

### 在 Electron 中使用

在主进程使用：

```javascript
// main.js
const { app, BrowserWindow } = require('electron');
const {
  generateRSAKeyPair,
  rsaEncrypt,
  rsaDecrypt
} = require('rust-crypto-electron');

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  mainWindow.loadFile('index.html');

  // 为渲染进程提供加密功能
  mainWindow.webContents.executeJavaScript(`
    const {
      generateRSAKeyPair,
      rsaEncrypt,
      rsaDecrypt
    } = require('rust-crypto-electron');

    window.cryptoLib = {
      generateRSAKeyPair,
      rsaEncrypt,
      rsaDecrypt
    };
  `);
}

app.whenReady().then(createWindow);
```

在渲染进程使用：

```html
<!-- index.html -->
<!DOCTYPE html>
<html>
<head>
  <title>rustCrypto Electron 示例</title>
</head>
<body>
  <h1>rustCrypto Electron 示例</h1>
  <button onclick="generateKeys()">生成密钥对</button>
  <button onclick="encryptData()">加密数据</button>
  <button onclick="decryptData()">解密数据</button>

  <div id="output"></div>

  <script>
    let currentKeyPair = null;

    function generateKeys() {
      currentKeyPair = window.cryptoLib.generateRSAKeyPair(2048);
      document.getElementById('output').innerHTML =
        `公钥: ${currentKeyPair.public_key.substring(0, 50)}...<br>` +
        `私钥: ${currentKeyPair.private_key.substring(0, 50)}...`;
    }

    function encryptData() {
      if (!currentKeyPair) {
        alert('请先生成密钥对');
        return;
      }

      const plaintext = 'Hello, Electron!';
      const encrypted = window.cryptoLib.rsaEncrypt(
        currentKeyPair.public_key,
        plaintext
      );

      document.getElementById('output').innerHTML = `加密结果: ${encrypted}`;
    }

    function decryptData() {
      if (!currentKeyPair) {
        alert('请先生成密钥对');
        return;
      }

      const encrypted = document.getElementById('output').textContent.replace('加密结果: ', '');
      const decrypted = window.cryptoLib.rsaDecrypt(
        currentKeyPair.private_key,
        encrypted
      );

      document.getElementById('output').innerHTML = `解密结果: ${decrypted}`;
    }
  </script>
</body>
</html>
```

## API 文档

### RSA 加密

#### generateRSAKeyPair(bits: number): KeyPair

生成 RSA 密钥对。

**参数：**
- `bits`: 密钥长度，2048 或 4096 等

**返回：**
- `KeyPair`: 包含 public_key 和 private_key 的对象

#### rsaEncrypt(publicKey: string, plaintext: string): string

使用 RSA 公钥加密数据。

**参数：**
- `publicKey`: PEM 格式的公钥
- `plaintext`: 要加密的字符串

**返回：**
- `string`: Base64 编码的密文

#### rsaDecrypt(privateKey: string, ciphertext: string): string

使用 RSA 私钥解密数据。

**参数：**
- `privateKey`: PEM 格式的私钥
- `ciphertext`: Base64 编码的密文

**返回：**
- `string`: 解密后的字符串

### AES 加密

#### generateAESKey(): string

生成 AES-256 密钥。

**返回：**
- `string`: Base64 编码的 32 字节密钥

#### aesEncrypt(key: string, plaintext: string): EncryptedData

使用 AES-256-GCM 加密数据。

**参数：**
- `key`: Base64 编码的 AES-256 密钥
- `plaintext`: 要加密的字符串

**返回：**
- `EncryptedData`: 包含 ciphertext 和 nonce 的对象

#### aesDecrypt(key: string, encryptedData: EncryptedData): string

使用 AES-256-GCM 解密数据。

**参数：**
- `key`: Base64 编码的 AES-256 密钥
- `encryptedData`: 加密数据对象

**返回：**
- `string`: 解密后的字符串

### 数据类型

#### KeyPair

```typescript
interface KeyPair {
  public_key: string;
  private_key: string;
}
```

#### EncryptedData

```typescript
interface EncryptedData {
  ciphertext: string;
  nonce: string;
}
```

## 构建

### 构建当前平台

```bash
npm install
npm run build
```

### 构建所有平台

```bash
npm run build:release -- --platform
```

这将为所有平台生成预编译的二进制文件：
- macOS (x86_64)
- macOS (ARM64)
- Linux (x86_64)
- Windows (x86_64)

### 构建调试版本

```bash
npm run build:debug
```

## TypeScript 支持

模块包含 TypeScript 类型定义，可开箱即用：

```typescript
import {
  generateRSAKeyPair,
  rsaEncrypt,
  rsaDecrypt,
  generateAESKey,
  aesEncrypt,
  aesDecrypt
} from 'rust-crypto-electron';

const keyPair: KeyPair = generateRSAKeyPair(2048);
const encrypted: string = rsaEncrypt(keyPair.public_key, 'Hello');
const decrypted: string = rsaDecrypt(keyPair.private_key, encrypted);
```

## 常见问题排查

### 安装失败

如果安装失败，请检查：

1. Node.js 版本是否 >= 16
2. Rust 是否已安装
3. Python 是否已安装（Windows 需要）
3. C++ 编译工具链是否已安装

### 构建失败

如果构建失败，请检查：

1. Rust 编译工具是否正确安装
2. CMake 是否已安装
3. 平台特定的构建依赖是否满足

### 运行时错误

如果运行时出现错误，请检查：

1. Node.js 模块正确加载
2. 密钥格式正确
3. 数据格式有效

### Electron 打包问题

如果 Electron 打包遇到问题，请检查：

1. 确保 rebuild 步骤正确执行
2. 检查 native 模块是否正确包含
3. 使用 electron-builder 或 electron-packager 时正确配置

## 示例

查看 `index.js` 文件了解更多使用示例。

## 许可证

MIT License