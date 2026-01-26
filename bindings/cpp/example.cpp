#include "CryptoLib.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <openssl/base64.h>

std::string base64Encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    
    BIO_free_all(bio);
    
    return result;
}

std::vector<uint8_t> stringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

int main() {
    try {
        std::cout << "=== RSA 加解密示例 ===" << std::endl;
        
        // 生成 RSA 密钥对
        auto rsaKeyPair = crypto::CryptoLib::generateRSAKeyPair(2048);
        std::cout << "RSA 密钥对生成成功" << std::endl;
        std::cout << "公钥长度: " << rsaKeyPair->getPublicKey().length() << " 字节" << std::endl;
        std::cout << "私钥长度: " << rsaKeyPair->getPrivateKey().length() << " 字节" << std::endl << std::endl;
        
        // RSA 加密
        std::string plaintext = "Hello, RSA from C++!";
        std::cout << "原始数据: " << plaintext << std::endl;
        
        auto plaintextBytes = stringToBytes(plaintext);
        auto encrypted = crypto::CryptoLib::rsaEncrypt(rsaKeyPair->getPublicKey(), plaintextBytes);
        
        std::cout << "加密后 (Base64): " << base64Encode(encrypted->toVector()) << std::endl;
        
        // RSA 解密
        auto decrypted = crypto::CryptoLib::rsaDecrypt(rsaKeyPair->getPrivateKey(), encrypted->toVector());
        std::cout << "解密后: " << decrypted->toString() << std::endl << std::endl;
        
        std::cout << "=== AES-GCM 加解密示例 ===" << std::endl;
        
        // 生成 AES 密钥
        auto aesKey = crypto::CryptoLib::generateAESKey();
        std::cout << "AES-256 密钥生成成功" << std::endl;
        std::cout << "密钥 (Base64): " << base64Encode(aesKey->toVector()) << std::endl << std::endl;
        
        // AES-GCM 加密
        std::string plaintext2 = "Hello, AES-GCM from C++!";
        std::cout << "原始数据: " << plaintext2 << std::endl;
        
        auto plaintextBytes2 = stringToBytes(plaintext2);
        auto encryptedData = crypto::CryptoLib::aesGCMEncrypt(aesKey->toVector(), plaintextBytes2);
        
        std::cout << "密文 (Base64): " << encryptedData->getCiphertext() << std::endl;
        std::cout << "Nonce (Base64): " << encryptedData->getNonce() << std::endl;
        std::cout << "Tag (Base64): " << encryptedData->getTag() << std::endl;
        
        // AES-GCM 解密
        auto decrypted2 = crypto::CryptoLib::aesGCMDecrypt(aesKey->toVector(), *encryptedData);
        std::cout << "解密后: " << decrypted2->toString() << std::endl << std::endl;
        
        std::cout << "库版本: " << crypto::CryptoLib::getVersion() << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}