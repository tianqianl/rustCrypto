use bitcoin::secp256k1::{Secp256k1, PublicKey, SecretKey, Message, ecdsa::Signature};
use bitcoin::bip32::{Xpriv, DerivationPath};
use bs58;
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone)]
pub struct EccKeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub struct EccEngine;

impl EccEngine {
    /// Generate a new ECC key pair (secp256k1)
    pub fn generate_key() -> Result<EccKeyPair, String> {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let private_bytes = secret_key.secret_bytes();
        let public_bytes = public_key.serialize_uncompressed();

        Ok(EccKeyPair {
            private_key: bs58::encode(private_bytes).into_string(),
            public_key: bs58::encode(public_bytes).into_string(),
        })
    }

    /// Get key by seed and derivation path (BIP32)
    /// seed: seed string
    /// path: derivation path string, e.g., "m/44'/60'/0'/0/0"
    pub fn get_key_by_seed_and_path(seed: &str, path: &str) -> Result<EccKeyPair, String> {
        let secp = Secp256k1::new();

        // Use seed bytes directly (same as Go's hdwallet.NewFromSeed)
        let seed_bytes = seed.as_bytes();

        // Create master key from seed
        let master_key = Xpriv::new_master(bitcoin::Network::Bitcoin, seed_bytes)
            .map_err(|e| format!("Failed to create master key: {:?}", e))?;

        // Parse derivation path
        let derivation_path: DerivationPath = path.parse()
            .map_err(|e| format!("Invalid derivation path: {:?}", e))?;

        // Derive child key
        let child_key = master_key.derive_priv(&secp, &derivation_path)
            .map_err(|e| format!("Failed to derive child key: {:?}", e))?;

        // Get private and public key bytes
        let private_bytes = child_key.private_key.secret_bytes();
        let public_bytes = child_key.private_key.public_key(&secp).serialize_uncompressed();

        Ok(EccKeyPair {
            private_key: bs58::encode(private_bytes).into_string(),
            public_key: bs58::encode(public_bytes).into_string(),
        })
    }

    /// Unmarshal private key from Base58 string
    pub fn unmarshal_private_key(key: &str) -> Result<[u8; 32], String> {
        let decoded = bs58::decode(key).into_vec()
            .map_err(|e| format!("Failed to decode Base58: {:?}", e))?;

        if decoded.len() != 32 {
            return Err(format!("Invalid private key length: {} (expected 32)", decoded.len()));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decoded[..32]);
        Ok(key_bytes)
    }

    /// Sign message using private key string
    pub fn sign_by_private_key_str(message: &[u8], private_key: &str) -> Result<Vec<u8>, String> {
        let private_bytes = Self::unmarshal_private_key(private_key)?;
        Self::sign(message, &private_bytes)
    }

    /// Sign message using private key bytes
    /// Note: message must be a 32-byte hash, not the original message
    pub fn sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| format!("Invalid private key: {:?}", e))?;

        let secp = Secp256k1::new();
        
        // message is expected to be a 32-byte hash (digest)
        let msg = Message::from_digest(message.try_into()
            .map_err(|_| "message must be exactly 32 bytes".to_string())?);

        let signature = secp.sign_ecdsa(&msg, &secret_key);

        // Serialize signature as DER format (same as Go)
        Ok(signature.serialize_der().to_vec())
    }

    /// Unmarshal public key from Base58 string
    pub fn unmarshal_public_key(public_key: &str) -> Result<PublicKey, String> {
        let decoded = bs58::decode(public_key).into_vec()
            .map_err(|e| format!("Failed to decode Base58: {:?}", e))?;

        PublicKey::from_slice(&decoded)
            .map_err(|e| format!("Invalid public key: {:?}", e))
    }

    /// Get address from public key string (Ethereum address format)
    pub fn get_address_by_pub_key_str(public_key: &str) -> Result<Vec<u8>, String> {
        let public_key_obj = Self::unmarshal_public_key(public_key)?;

        let uncompressed = public_key_obj.serialize_uncompressed();

        if uncompressed.len() != 65 {
            return Err(format!("Invalid uncompressed public key length: {}", uncompressed.len()));
        }

        // Keccak256 hash of the public key
        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed[1..]);
        let hash = hasher.finalize();

        // Last 20 bytes is the address
        Ok(hash[12..].to_vec())
    }

    /// Verify signature
    pub fn verify_sign(message: &[u8], signature: &[u8], public_key: &str) -> Result<bool, String> {
        let verifying_key = Self::unmarshal_public_key(public_key)?;

        let secp = Secp256k1::new();
        
        // message is expected to be a 32-byte hash (digest)
        let msg = Message::from_digest(message.try_into()
            .map_err(|_| "message must be exactly 32 bytes".to_string())?);

        let signature = Signature::from_der(signature)
            .map_err(|e| format!("Invalid signature format: {:?}", e))?;

        Ok(secp.verify_ecdsa(&msg, &signature, &verifying_key).is_ok())
    }

    /// Base58 encode
    pub fn base58_encode(data: &[u8]) -> String {
        bs58::encode(data).into_string()
    }

    /// Base58 decode
    pub fn base58_decode(encoded: &str) -> Result<Vec<u8>, String> {
        bs58::decode(encoded).into_vec()
            .map_err(|e| format!("Base58 decode failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let keypair = EccEngine::generate_key().unwrap();
        assert!(!keypair.private_key.is_empty());
        assert!(!keypair.public_key.is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = EccEngine::generate_key().unwrap();
        let message = b"Hello, ECC!";

        let signature = EccEngine::sign_by_private_key_str(message, &keypair.private_key).unwrap();
        let is_valid = EccEngine::verify_sign(message, &signature, &keypair.public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_get_address() {
        let keypair = EccEngine::generate_key().unwrap();
        let address = EccEngine::get_address_by_pub_key_str(&keypair.public_key).unwrap();
        assert_eq!(address.len(), 20);
    }

    #[test]
    fn test_base58_encode_decode() {
        let data = b"Hello, Base58!";
        let encoded = EccEngine::base58_encode(data);
        let decoded = EccEngine::base58_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_get_key_by_seed_and_path() {
        let seed = "my_seed_phrase_12345";
        let path = "m/44'/60'/0'/0/0";

        let keypair = EccEngine::get_key_by_seed_and_path(seed, path).unwrap();
        assert!(!keypair.private_key.is_empty());
        assert!(!keypair.public_key.is_empty());

        // Verify the key can be used for signing
        let message = b"Test message";
        let signature = EccEngine::sign_by_private_key_str(message, &keypair.private_key).unwrap();
        let is_valid = EccEngine::verify_sign(message, &signature, &keypair.public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn verification_test_generate_key() {
        println!("\n=== 测试 1: GenerateKey 生成密钥对 ===");

        let keypair = EccEngine::generate_key().unwrap();

        println!("Rust 私钥 (Base58): {}", keypair.private_key);
        println!("Rust 公钥 (Base58): {}", keypair.public_key);

        // 测试签名和验证
        let message = b"Hello, ECC Cross-Validation!";
        let signature = EccEngine::sign_by_private_key_str(message, &keypair.private_key).unwrap();
        println!("消息: {}", String::from_utf8_lossy(message));
        println!("签名 (Hex): {}", hex::encode(&signature));

        let is_valid = EccEngine::verify_sign(message, &signature, &keypair.public_key).unwrap();
        println!("验证结果: {}", is_valid);
        assert!(is_valid, "签名验证应该成功");

        // 获取地址
        let address = EccEngine::get_address_by_pub_key_str(&keypair.public_key).unwrap();
        println!("地址 (Hex): {}", hex::encode(&address));
        assert_eq!(address.len(), 20, "地址应该是20字节");
    }

    #[test]
    fn verification_test_get_key_by_seed_and_path() {
        println!("\n=== 测试 2: GetKeyBySeedAndPath 通过种子和路径生成密钥 ===");

        let seed = "my_test_seed_12345";
        let path = "m/44'/60'/0'/0/0";

        println!("种子: {}", seed);
        println!("路径: {}", path);

        let keypair = EccEngine::get_key_by_seed_and_path(seed, path).unwrap();

        println!("Rust 私钥 (Base58): {}", keypair.private_key);
        println!("Rust 公钥 (Base58): {}", keypair.public_key);

        // 测试签名和验证
        let message = b"Hello, ECC Cross-Validation!";
        let signature = EccEngine::sign_by_private_key_str(message, &keypair.private_key).unwrap();
        println!("消息: {}", String::from_utf8_lossy(message));
        println!("签名 (Hex): {}", hex::encode(&signature));

        let is_valid = EccEngine::verify_sign(message, &signature, &keypair.public_key).unwrap();
        println!("验证结果: {}", is_valid);
        assert!(is_valid, "签名验证应该成功");

        // 获取地址
        let address = EccEngine::get_address_by_pub_key_str(&keypair.public_key).unwrap();
        println!("地址 (Hex): {}", hex::encode(&address));
        assert_eq!(address.len(), 20, "地址应该是20字节");
    }

    #[test]
    fn verification_test_consistency() {
        println!("\n=== 测试 3: 一致性验证 ===");

        let seed = "consistency_test_seed";
        let path = "m/44'/60'/0'/0/1";

        println!("使用相同的种子和路径多次生成密钥，验证一致性:");
        println!("种子: {}", seed);
        println!("路径: {}", path);

        let keypair1 = EccEngine::get_key_by_seed_and_path(seed, path).unwrap();
        let keypair2 = EccEngine::get_key_by_seed_and_path(seed, path).unwrap();

        println!("第一次生成:");
        println!("  私钥: {}", keypair1.private_key);
        println!("  公钥: {}", keypair1.public_key);

        println!("第二次生成:");
        println!("  私钥: {}", keypair2.private_key);
        println!("  公钥: {}", keypair2.public_key);

        assert_eq!(keypair1.private_key, keypair2.private_key, "私钥应该一致");
        assert_eq!(keypair1.public_key, keypair2.public_key, "公钥应该一致");

        // 验证签名一致性
        let message = b"Consistency test message";
        let sig1 = EccEngine::sign_by_private_key_str(message, &keypair1.private_key).unwrap();
        let sig2 = EccEngine::sign_by_private_key_str(message, &keypair2.private_key).unwrap();

        println!("消息: {}", String::from_utf8_lossy(message));
        println!("第一次签名 (Hex): {}", hex::encode(&sig1));
        println!("第二次签名 (Hex): {}", hex::encode(&sig2));

        assert_eq!(sig1, sig2, "相同私钥对相同消息的签名应该一致");

        let valid1 = EccEngine::verify_sign(message, &sig1, &keypair1.public_key).unwrap();
        let valid2 = EccEngine::verify_sign(message, &sig2, &keypair2.public_key).unwrap();

        println!("第一次验证结果: {}", valid1);
        println!("第二次验证结果: {}", valid2);

        assert!(valid1, "第一次签名验证应该成功");
        assert!(valid2, "第二次签名验证应该成功");
    }

    #[test]
    fn verification_test_base58() {
        println!("\n=== 测试 4: Base58 编码解码 ===");

        let test_data = b"Hello, Base58!";

        let encoded = EccEngine::base58_encode(test_data);
        println!("原始数据: {}", String::from_utf8_lossy(test_data));
        println!("Base58 编码: {}", encoded);

        let decoded = EccEngine::base58_decode(&encoded).unwrap();
        println!("解码后: {}", String::from_utf8_lossy(&decoded));

        assert_eq!(test_data.as_slice(), decoded.as_slice(), "编码解码应该一致");
    }

    #[test]
    fn verification_test_multiple_derivations() {
        println!("\n=== 测试 5: 多个派生路径 ===");

        let seed = "multi_derivation_seed";
        let paths = vec![
            "m/44'/60'/0'/0/0",
            "m/44'/60'/0'/0/1",
            "m/44'/60'/0'/0/2",
        ];

        println!("种子: {}", seed);

        for (i, path) in paths.iter().enumerate() {
            println!("\n路径 {}: {}", i, path);

            let keypair = EccEngine::get_key_by_seed_and_path(seed, path).unwrap();
            println!("  私钥: {}", keypair.private_key);
            println!("  公钥: {}", keypair.public_key);

            let message = format!("Message for path {}", i);
            let signature = EccEngine::sign_by_private_key_str(message.as_bytes(), &keypair.private_key).unwrap();
            let is_valid = EccEngine::verify_sign(message.as_bytes(), &signature, &keypair.public_key).unwrap();

            println!("  签名 (Hex): {}", hex::encode(&signature));
            println!("  验证结果: {}", is_valid);
            assert!(is_valid, "路径 {} 的签名验证应该成功", i);
        }
    }
}

#[test]
fn test_public_key_length() {
    let keypair = EccEngine::generate_key().unwrap();
    let public_key_bytes = bs58::decode(keypair.public_key).into_vec().unwrap();
    println!("公钥长度: {} 字节", public_key_bytes.len());
    println!("公钥第一个字节: 0x{:02x}", public_key_bytes[0]);
    assert_eq!(public_key_bytes.len(), 65, "公钥应该是65字节（未压缩格式）");
    assert_eq!(public_key_bytes[0], 0x04, "公钥第一个字节应该是0x04（未压缩格式）");
}
