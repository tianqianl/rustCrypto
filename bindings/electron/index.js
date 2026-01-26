const { generateRSAKeyPair, rsaEncrypt, rsaDecrypt, generateAESKey, aesEncrypt, aesDecrypt } = require('./index.node');

/**
 * RSA 加密/解密示例
 */
function rsaExample() {
    console.log('=== RSA 加密/解密示例 ===');
    
    // 生成 RSA 密钥对
    const keyPair = generateRSAKeyPair(2048);
    console.log('RSA 密钥对生成成功');
    
    // RSA 加密
    const plaintext = 'Hello, RSA!';
    const encrypted = rsaEncrypt(keyPair.publicKey, plaintext);
    console.log('加密结果:', encrypted);
    
    // RSA 解密
    const decrypted = rsaDecrypt(keyPair.privateKey, encrypted);
    console.log('解密结果:', decrypted);
    console.log('解密成功:', plaintext === decrypted);
    console.log();
}

/**
 * AES 加密/解密示例
 */
function aesExample() {
    console.log('=== AES 加密/解密示例 ===');
    
    // 生成 AES 密钥
    const aesKey = generateAESKey();
    console.log('AES 密钥生成成功');
    
    // AES 加密
    const plaintext = 'Hello, AES!';
    const encryptedData = aesEncrypt(aesKey, plaintext);
    console.log('加密结果:', encryptedData);
    
    // AES 解密
    const decrypted = aesDecrypt(aesKey, encryptedData);
    console.log('解密结果:', decrypted);
    console.log('解密成功:', plaintext === decrypted);
    console.log();
}

// 运行示例
try {
    rsaExample();
    aesExample();
    console.log('所有测试通过!');
} catch (error) {
    console.error('测试失败:', error);
    process.exit(1);
}

module.exports = {
    generateRSAKeyPair,
    rsaEncrypt,
    rsaDecrypt,
    generateAESKey,
    aesEncrypt,
    aesDecrypt
};