use rsa::{RsaPrivateKey, RsaPublicKey};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, AeadCore, OsRng};
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};
use pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePrivateKey, DecodePublicKey};
use spki::der::pem::LineEnding;
use rand::RngCore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: String,
    pub nonce: String,
}

pub struct CryptoEngine;

impl CryptoEngine {
    pub fn generate_rsa_keypair(bits: u32) -> Result<KeyPair, String> {
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits as usize)
            .map_err(|e| format!("Failed to generate RSA key: {}", e))?;
        
        let public_key = RsaPublicKey::from(&private_key);
        
        let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to export private key: {}", e))?
            .to_string();
        
        let public_key_pem = public_key.to_public_key_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to export public key: {}", e))?;
        
        Ok(KeyPair {
            public_key: public_key_pem,
            private_key: private_key_pem,
        })
    }

    pub fn rsa_encrypt(public_key_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
            .map_err(|e| format!("Failed to parse public key: {}", e))?;
        
        let mut rng = rand::rngs::OsRng;
        let padding = rsa::Pkcs1v15Encrypt;
        
        let encrypted = public_key.encrypt(&mut rng, padding, plaintext)
            .map_err(|e| format!("RSA encryption failed: {}", e))?;
        
        Ok(encrypted)
    }

    pub fn rsa_decrypt(private_key_pem: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| format!("Failed to parse private key: {}", e))?;
        
        let padding = rsa::Pkcs1v15Encrypt;
        
        let decrypted = private_key.decrypt(padding, ciphertext)
            .map_err(|e| format!("RSA decryption failed: {}", e))?;
        
        Ok(decrypted)
    }

    pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<EncryptedData, String> {
        if key.len() != 32 {
            return Err("AES-256 key must be 32 bytes".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Failed to create AES-GCM cipher: {}", e))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

        Ok(EncryptedData {
            ciphertext: general_purpose::STANDARD.encode(&ciphertext),
            nonce: general_purpose::STANDARD.encode(&nonce),
        })
    }

    pub fn aes_gcm_decrypt(key: &[u8], encrypted_data: &EncryptedData) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("AES-256 key must be 32 bytes".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Failed to create AES-GCM cipher: {}", e))?;

        let ciphertext_bytes = general_purpose::STANDARD.decode(&encrypted_data.ciphertext)
            .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

        let nonce_bytes = general_purpose::STANDARD.decode(&encrypted_data.nonce)
            .map_err(|e| format!("Failed to decode nonce: {}", e))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher.decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;

        Ok(decrypted)
    }

    pub fn generate_aes_key() -> Result<Vec<u8>, String> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Ok(key.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_generation() {
        let keypair = CryptoEngine::generate_rsa_keypair(2048).unwrap();
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.private_key.is_empty());
    }

    #[test]
    fn test_rsa_encryption_decryption() {
        let keypair = CryptoEngine::generate_rsa_keypair(2048).unwrap();
        let plaintext = b"Hello, RSA!";
        
        let encrypted = CryptoEngine::rsa_encrypt(&keypair.public_key, plaintext).unwrap();
        let decrypted = CryptoEngine::rsa_decrypt(&keypair.private_key, &encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_encryption_decryption() {
        let key = CryptoEngine::generate_aes_key().unwrap();
        let plaintext = b"Hello, AES-GCM!";
        
        let encrypted = CryptoEngine::aes_gcm_encrypt(&key, plaintext).unwrap();
        let decrypted = CryptoEngine::aes_gcm_decrypt(&key, &encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}