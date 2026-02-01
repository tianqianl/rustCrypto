package com.crypto.lib

object CryptoLib {
    init {
        System.loadLibrary("crypto_lib")
    }

    external fun generateRSAKeyPair(bits: Int): KeyPair?

    external fun rsaEncrypt(publicKey: String, plaintext: ByteArray): ByteArray?

    external fun rsaDecrypt(privateKey: String, ciphertext: ByteArray): ByteArray?

    external fun generateAESKey(): ByteArray?

    external fun aesGCMEncrypt(key: ByteArray, plaintext: ByteArray): EncryptedData?

    external fun aesGCMDecrypt(key: ByteArray, encryptedData: EncryptedData): ByteArray?

    external fun getVersion(): String
}

data class KeyPair(
    val publicKey: String,
    val privateKey: String
)

data class EncryptedData(
    val ciphertext: String,
    val nonce: String
)