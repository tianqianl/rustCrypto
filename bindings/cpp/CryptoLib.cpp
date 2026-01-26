#include "CryptoLib.hpp"
#include <stdexcept>
#include <openssl/base64.h>

namespace crypto {

std::string ByteArray::toBase64() const {
    if (!data_ || len_ == 0) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data_, static_cast<int>(len_));
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    
    BIO_free_all(bio);
    
    return result;
}

std::unique_ptr<KeyPair> CryptoLib::generateRSAKeyPair(int bits) {
    CKeyPair* cKeyPair = crypto_generate_rsa_keypair(bits);
    
    if (!cKeyPair) {
        throw std::runtime_error("Failed to generate RSA key pair");
    }
    
    std::string publicKey(cKeyPair->public_key);
    std::string privateKey(cKeyPair->private_key);
    
    crypto_free_keypair(cKeyPair);
    
    return std::make_unique<KeyPair>(publicKey, privateKey);
}

std::unique_ptr<ByteArray> CryptoLib::rsaEncrypt(
    const std::string& publicKey,
    const std::vector<uint8_t>& plaintext
) {
    size_t outLen = 0;
    
    CByteArray* cResult = crypto_rsa_encrypt(
        publicKey.c_str(),
        plaintext.data(),
        plaintext.size(),
        &outLen
    );
    
    if (!cResult) {
        throw std::runtime_error("RSA encryption failed");
    }
    
    return std::make_unique<ByteArray>(cResult->data, outLen);
}

std::unique_ptr<ByteArray> CryptoLib::rsaDecrypt(
    const std::string& privateKey,
    const std::vector<uint8_t>& ciphertext
) {
    size_t outLen = 0;
    
    CByteArray* cResult = crypto_rsa_decrypt(
        privateKey.c_str(),
        ciphertext.data(),
        ciphertext.size(),
        &outLen
    );
    
    if (!cResult) {
        throw std::runtime_error("RSA decryption failed");
    }
    
    return std::make_unique<ByteArray>(cResult->data, outLen);
}

std::unique_ptr<ByteArray> CryptoLib::generateAESKey() {
    size_t outLen = 0;
    
    CByteArray* cResult = crypto_generate_aes_key(&outLen);
    
    if (!cResult) {
        throw std::runtime_error("Failed to generate AES key");
    }
    
    return std::make_unique<ByteArray>(cResult->data, outLen);
}

std::unique_ptr<EncryptedData> CryptoLib::aesGCMEncrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext
) {
    if (key.size() != 32) {
        throw std::runtime_error("AES key must be 32 bytes");
    }
    
    CEncryptedData* cResult = crypto_aes_gcm_encrypt(
        key.data(),
        key.size(),
        plaintext.data(),
        plaintext.size()
    );
    
    if (!cResult) {
        throw std::runtime_error("AES-GCM encryption failed");
    }
    
    std::string ciphertext(cResult->ciphertext);
    std::string nonce(cResult->nonce);
    std::string tag(cResult->tag);
    
    crypto_free_encrypted_data(cResult);
    
    return std::make_unique<EncryptedData>(ciphertext, nonce, tag);
}

std::unique_ptr<ByteArray> CryptoLib::aesGCMDecrypt(
    const std::vector<uint8_t>& key,
    const EncryptedData& encryptedData
) {
    if (key.size() != 32) {
        throw std::runtime_error("AES key must be 32 bytes");
    }
    
    CEncryptedData cEncryptedData;
    cEncryptedData.ciphertext = const_cast<char*>(encryptedData.getCiphertext().c_str());
    cEncryptedData.nonce = const_cast<char*>(encryptedData.getNonce().c_str());
    cEncryptedData.tag = const_cast<char*>(encryptedData.getTag().c_str());
    
    size_t outLen = 0;
    
    CByteArray* cResult = crypto_aes_gcm_decrypt(
        key.data(),
        key.size(),
        &cEncryptedData,
        &outLen
    );
    
    if (!cResult) {
        throw std::runtime_error("AES-GCM decryption failed");
    }
    
    return std::make_unique<ByteArray>(cResult->data, outLen);
}

std::string CryptoLib::getVersion() {
    const char* version = crypto_get_version();
    return std::string(version);
}

} // namespace crypto