package com.crypto.example

import android.os.Bundle
import android.util.Base64
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.crypto.lib.CryptoLib
import com.crypto.lib.EncryptedData
import com.crypto.lib.KeyPair
import kotlin.text.Charsets.UTF_8

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val textView = TextView(this)
        textView.text = "加解密库示例\n\n"
        
        try {
            // RSA 加解密示例
            textView.append("=== RSA 加解密示例 ===\n")
            
            val rsaKeyPair: KeyPair = CryptoLib.generateRSAKeyPair(2048) ?: run {
                textView.append("RSA 密钥对生成失败\n")
                return
            }
            
            textView.append("RSA 密钥对生成成功\n")
            textView.append("公钥长度: ${rsaKeyPair.publicKey.length} 字节\n")
            textView.append("私钥长度: ${rsaKeyPair.privateKey.length} 字节\n\n")
            
            val plaintext = "Hello, RSA from Android!".toByteArray(UTF_8)
            textView.append("原始数据: ${String(plaintext)}\n")
            
            val encrypted = CryptoLib.rsaEncrypt(rsaKeyPair.publicKey, plaintext)
            if (encrypted != null) {
                textView.append("加密后 (Base64): ${Base64.encodeToString(encrypted, Base64.NO_WRAP)}\n")
                
                val decrypted = CryptoLib.rsaDecrypt(rsaKeyPair.privateKey, encrypted)
                if (decrypted != null) {
                    textView.append("解密后: ${String(decrypted)}\n\n")
                } else {
                    textView.append("解密失败\n\n")
                }
            } else {
                textView.append("加密失败\n\n")
            }
            
            // AES-GCM 加解密示例
            textView.append("=== AES-GCM 加解密示例 ===\n")
            
            val aesKey = CryptoLib.generateAESKey()
            if (aesKey != null) {
                textView.append("AES-256 密钥生成成功\n")
                textView.append("密钥 (Base64): ${Base64.encodeToString(aesKey, Base64.NO_WRAP)}\n\n")
                
                val plaintext2 = "Hello, AES-GCM from Android!".toByteArray(UTF_8)
                textView.append("原始数据: ${String(plaintext2)}\n")
                
                val encryptedData: EncryptedData = CryptoLib.aesGCMEncrypt(aesKey, plaintext2) ?: run {
                    textView.append("加密失败\n\n")
                    return
                }
                
                textView.append("密文 (Base64): ${encryptedData.ciphertext}\n")
                textView.append("Nonce (Base64): ${encryptedData.nonce}\n")
                textView.append("Tag (Base64): ${encryptedData.tag}\n")
                
                val decrypted2 = CryptoLib.aesGCMDecrypt(aesKey, encryptedData)
                if (decrypted2 != null) {
                    textView.append("解密后: ${String(decrypted2)}\n\n")
                } else {
                    textView.append("解密失败\n\n")
                }
            } else {
                textView.append("AES 密钥生成失败\n\n")
            }
            
            textView.append("库版本: ${CryptoLib.getVersion()}\n")
            
        } catch (e: Exception) {
            textView.append("错误: ${e.message}\n")
            e.printStackTrace()
        }
        
        setContentView(textView)
    }
}