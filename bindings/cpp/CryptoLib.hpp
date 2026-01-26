#ifndef CRYPTO_LIB_HPP
#define CRYPTO_LIB_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

extern "C" {
    #include "crypto.h"
}

namespace crypto {

class ByteArray {
public:
    ByteArray() : data_(nullptr), len_(0) {}
    
    ByteArray(uint8_t* data, size_t len) : data_(data), len_(len) {}
    
    ~ByteArray() {
        if (data_) {
            crypto_free_byte_array(reinterpret_cast<CByteArray*>(this));
            data_ = nullptr;
        }
    }
    
    ByteArray(const ByteArray&) = delete;
    ByteArray& operator=(const ByteArray&) = delete;
    
    ByteArray(ByteArray&& other) noexcept : data_(other.data_), len_(other.len_) {
        other.data_ = nullptr;
        other.len_ = 0;
    }
    
    ByteArray& operator=(ByteArray&& other) noexcept {
        if (this != &other) {
            if (data_) {
                crypto_free_byte_array(reinterpret_cast<CByteArray*>(this));
            }
            data_ = other.data_;
            len_ = other.len_;
            other.data_ = nullptr;
            other.len_ = 0;
        }
        return *this;
    }
    
    const uint8_t* data() const { return data_; }
    size_t size() const { return len_; }
    
    std::vector<uint8_t> toVector() const {
        return std::vector<uint8_t>(data_, data_ + len_);
    }
    
    std::string toString() const {
        return std::string(reinterpret_cast<const char*>(data_), len_);
    }
    
    std::string toBase64() const;
    
private:
    uint8_t* data_;
    size_t len_;
};

class KeyPair {
public:
    KeyPair(const std::string& publicKey, const std::string& privateKey)
        : publicKey_(publicKey), privateKey_(privateKey) {}
    
    const std::string& getPublicKey() const { return publicKey_; }
    const std::string& getPrivateKey() const { return privateKey_; }
    
private:
    std::string publicKey_;
    std::string privateKey_;
};

class EncryptedData {
public:
    EncryptedData(const std::string& ciphertext, const std::string& nonce, const std::string& tag)
        : ciphertext_(ciphertext), nonce_(nonce), tag_(tag) {}
    
    const std::string& getCiphertext() const { return ciphertext_; }
    const std::string& getNonce() const { return nonce_; }
    const std::string& getTag() const { return tag_; }
    
private:
    std::string ciphertext_;
    std::string nonce_;
    std::string tag_;
};

class CryptoLib {
public:
    static std::unique_ptr<KeyPair> generateRSAKeyPair(int bits);
    
    static std::unique_ptr<ByteArray> rsaEncrypt(
        const std::string& publicKey,
        const std::vector<uint8_t>& plaintext
    );
    
    static std::unique_ptr<ByteArray> rsaDecrypt(
        const std::string& privateKey,
        const std::vector<uint8_t>& ciphertext
    );
    
    static std::unique_ptr<ByteArray> generateAESKey();
    
    static std::unique_ptr<EncryptedData> aesGCMEncrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& plaintext
    );
    
    static std::unique_ptr<ByteArray> aesGCMDecrypt(
        const std::vector<uint8_t>& key,
        const EncryptedData& encryptedData
    );
    
    static std::string getVersion();
    
private:
    CryptoLib() = delete;
};

} // namespace crypto

#endif // CRYPTO_LIB_HPP