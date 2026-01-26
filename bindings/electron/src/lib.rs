use napi_derive::napi;
use crypto_lib::crypto::{CryptoEngine, KeyPair, EncryptedData};
use base64::{Engine as _, engine::general_purpose};

#[napi(object)]
pub struct NapiKeyPair {
    pub public_key: String,
    pub private_key: String,
}

#[napi(object)]
pub struct NapiEncryptedData {
    pub ciphertext: String,
    pub nonce: String,
}

impl From<KeyPair> for NapiKeyPair {
    fn from(pair: KeyPair) -> Self {
        NapiKeyPair {
            public_key: pair.public_key,
            private_key: pair.private_key,
        }
    }
}

impl From<EncryptedData> for NapiEncryptedData {
    fn from(data: EncryptedData) -> Self {
        NapiEncryptedData {
            ciphertext: data.ciphertext,
            nonce: data.nonce,
        }
    }
}

#[napi]
pub fn generate_rsa_keypair(bits: u32) -> NapiKeyPair {
    CryptoEngine::generate_rsa_keypair(bits)
        .expect("Failed to generate RSA key")
        .into()
}

#[napi]
pub fn rsa_encrypt(public_key_pem: String, plaintext: String) -> String {
    let encrypted = CryptoEngine::rsa_encrypt(&public_key_pem, plaintext.as_bytes())
        .expect("RSA encryption failed");
    general_purpose::STANDARD.encode(&encrypted)
}

#[napi]
pub fn rsa_decrypt(private_key_pem: String, ciphertext: String) -> String {
    let encrypted = general_purpose::STANDARD.decode(&ciphertext)
        .expect("Failed to decode ciphertext");
    let decrypted = CryptoEngine::rsa_decrypt(&private_key_pem, &encrypted)
        .expect("RSA decryption failed");
    String::from_utf8(decrypted).unwrap()
}

#[napi]
pub fn generate_aes_key() -> String {
    let key = CryptoEngine::generate_aes_key()
        .expect("Failed to generate AES key");
    general_purpose::STANDARD.encode(&key)
}

#[napi]
pub fn aes_encrypt(key: String, plaintext: String) -> NapiEncryptedData {
    let key_bytes = general_purpose::STANDARD.decode(&key)
        .expect("Failed to decode key");
    let encrypted = CryptoEngine::aes_gcm_encrypt(&key_bytes, plaintext.as_bytes())
        .expect("AES encryption failed");
    encrypted.into()
}

#[napi]
pub fn aes_decrypt(key: String, encrypted_data: NapiEncryptedData) -> String {
    let key_bytes = general_purpose::STANDARD.decode(&key)
        .expect("Failed to decode key");
    let encrypted = EncryptedData {
        ciphertext: encrypted_data.ciphertext,
        nonce: encrypted_data.nonce,
        tag: "".to_string(),
    };
    let decrypted = CryptoEngine::aes_gcm_decrypt(&key_bytes, &encrypted)
        .expect("AES decryption failed");
    String::from_utf8(decrypted).unwrap()
}