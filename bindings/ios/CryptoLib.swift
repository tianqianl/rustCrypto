import Foundation

public class CryptoLib {
    static let libraryName = "crypto_lib"
    
    private static func loadLibrary() {
        // iOS automatically loads libraries from the framework bundle
    }
    
    // MARK: - RSA Key Pair
    
    public struct KeyPair {
        public let publicKey: String
        public let privateKey: String
    }
    
    // MARK: - Encrypted Data
    
    public struct EncryptedData {
        public let ciphertext: String
        public let nonce: String
    }
    
    // MARK: - RSA Operations
    
    public static func generateRSAKeyPair(bits: Int) -> KeyPair? {
        guard let cKeyPair = crypto_generate_rsa_keypair(Int32(bits)) else {
            return nil
        }
        
        defer {
            crypto_free_keypair(cKeyPair)
        }
        
        let publicKey = String(cString: cKeyPair.pointee.public_key)
        let privateKey = String(cString: cKeyPair.pointee.private_key)
        
        return KeyPair(publicKey: publicKey, privateKey: privateKey)
    }
    
    public static func rsaEncrypt(publicKey: String, plaintext: Data) -> Data? {
        let publicKeyCString = publicKey.cString(using: .utf8)
        var outLen: size_t = 0
        
        plaintext.withUnsafeBytes { (rawBuffer) in
            guard let buffer = rawBuffer.baseAddress else { return }
            
            let cResult = crypto_rsa_encrypt(
                publicKeyCString,
                buffer.assumingMemoryBound(to: UInt8.self),
                plaintext.count,
                &outLen
            )
            
            guard let result = cResult else { return }
            defer { crypto_free_byte_array(result) }
            
            return Data(bytes: result.pointee.data, count: outLen)
        }
        
        return nil
    }
    
    public static func rsaDecrypt(privateKey: String, ciphertext: Data) -> Data? {
        let privateKeyCString = privateKey.cString(using: .utf8)
        var outLen: size_t = 0
        
        ciphertext.withUnsafeBytes { (rawBuffer) in
            guard let buffer = rawBuffer.baseAddress else { return }
            
            let cResult = crypto_rsa_decrypt(
                privateKeyCString,
                buffer.assumingMemoryBound(to: UInt8.self),
                ciphertext.count,
                &outLen
            )
            
            guard let result = cResult else { return }
            defer { crypto_free_byte_array(result) }
            
            return Data(bytes: result.pointee.data, count: outLen)
        }
        
        return nil
    }
    
    // MARK: - AES Operations
    
    public static func generateAESKey() -> Data? {
        var outLen: size_t = 0
        
        guard let cResult = crypto_generate_aes_key(&outLen) else {
            return nil
        }
        
        defer { crypto_free_byte_array(cResult) }
        
        return Data(bytes: cResult.pointee.data, count: outLen)
    }
    
    public static func aesGCMEncrypt(key: Data, plaintext: Data) -> EncryptedData? {
        guard key.count == 32 else { return nil }
        
        var outLen: size_t = 0
        
        let cResult = withUnsafeBytes(of: key) { keyBuffer in
            plaintext.withUnsafeBytes { plaintextBuffer in
                crypto_aes_gcm_encrypt(
                    keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    plaintextBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    plaintext.count
                )
            }
        }
        
        guard let result = cResult else { return nil }
        defer { crypto_free_encrypted_data(result) }
        
        let ciphertext = String(cString: result.pointee.ciphertext)
        let nonce = String(cString: result.pointee.nonce)

        return EncryptedData(ciphertext: ciphertext, nonce: nonce)
    }
    
    public static func aesGCMDecrypt(key: Data, encryptedData: EncryptedData) -> Data? {
        guard key.count == 32 else { return nil }
        
        var cEncryptedData = CEncryptedData()
        cEncryptedData.ciphertext = UnsafeMutablePointer<Int8>(mutating: (encryptedData.ciphertext as NSString).utf8String)
        cEncryptedData.nonce = UnsafeMutablePointer<Int8>(mutating: (encryptedData.nonce as NSString).utf8String)
        
        var outLen: size_t = 0
        
        let cResult = withUnsafeBytes(of: key) { keyBuffer in
            crypto_aes_gcm_decrypt(
                keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count,
                &cEncryptedData,
                &outLen
            )
        }
        
        guard let result = cResult else { return nil }
        defer { crypto_free_byte_array(result) }
        
        return Data(bytes: result.pointee.data, count: outLen)
    }
    
    // MARK: - Library Info
    
    public static func getVersion() -> String {
        guard let version = crypto_get_version() else {
            return "unknown"
        }
        return String(cString: version)
    }
}

// MARK: - C Function Declarations

@_silgen_name("crypto_generate_rsa_keypair")
private func crypto_generate_rsa_keypair(_ bits: Int32) -> UnsafeMutablePointer<CKeyPair>?

@_silgen_name("crypto_rsa_encrypt")
private func crypto_rsa_encrypt(
    _ publicKey: UnsafePointer<Int8>?,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintextLen: size_t,
    _ outLen: UnsafeMutablePointer<size_t>
) -> UnsafeMutablePointer<CByteArray>?

@_silgen_name("crypto_rsa_decrypt")
private func crypto_rsa_decrypt(
    _ privateKey: UnsafePointer<Int8>?,
    _ ciphertext: UnsafePointer<UInt8>?,
    _ ciphertextLen: size_t,
    _ outLen: UnsafeMutablePointer<size_t>
) -> UnsafeMutablePointer<CByteArray>?

@_silgen_name("crypto_aes_gcm_encrypt")
private func crypto_aes_gcm_encrypt(
    _ key: UnsafePointer<UInt8>?,
    _ keyLen: size_t,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintextLen: size_t
) -> UnsafeMutablePointer<CEncryptedData>?

@_silgen_name("crypto_aes_gcm_decrypt")
private func crypto_aes_gcm_decrypt(
    _ key: UnsafePointer<UInt8>?,
    _ keyLen: size_t,
    _ encryptedData: UnsafePointer<CEncryptedData>?,
    _ outLen: UnsafeMutablePointer<size_t>
) -> UnsafeMutablePointer<CByteArray>?

@_silgen_name("crypto_generate_aes_key")
private func crypto_generate_aes_key(_ outLen: UnsafeMutablePointer<size_t>) -> UnsafeMutablePointer<CByteArray>?

@_silgen_name("crypto_free_keypair")
private func crypto_free_keypair(_ keypair: UnsafeMutablePointer<CKeyPair>?)

@_silgen_name("crypto_free_encrypted_data")
private func crypto_free_encrypted_data(_ data: UnsafeMutablePointer<CEncryptedData>?)

@_silgen_name("crypto_free_byte_array")
private func crypto_free_byte_array(_ array: UnsafeMutablePointer<CByteArray>?)

@_silgen_name("crypto_get_version")
private func crypto_get_version() -> UnsafeMutablePointer<Int8>?

// MARK: - C Struct Definitions

private struct CKeyPair {
    var publicKey: UnsafeMutablePointer<Int8>?
    var privateKey: UnsafeMutablePointer<Int8>?
}

private struct CEncryptedData {
    var ciphertext: UnsafeMutablePointer<Int8>?
    var nonce: UnsafeMutablePointer<Int8>?
    var tag: UnsafeMutablePointer<Int8>?
}

private struct CByteArray {
    var data: UnsafeMutablePointer<UInt8>?
    var len: size_t
}