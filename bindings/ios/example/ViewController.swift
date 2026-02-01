import UIKit
import Foundation

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let textView = UITextView()
        textView.frame = view.bounds
        textView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        textView.isEditable = false
        textView.font = UIFont.systemFont(ofSize: 14)
        view.addSubview(textView)
        
        var output = "加解密库示例\n\n"
        
        // RSA 加解密示例
        output += "=== RSA 加解密示例 ===\n"
        
        if let rsaKeyPair = CryptoLib.generateRSAKeyPair(bits: 2048) {
            output += "RSA 密钥对生成成功\n"
            output += "公钥长度: \(rsaKeyPair.publicKey.count) 字节\n"
            output += "私钥长度: \(rsaKeyPair.privateKey.count) 字节\n\n"
            
            let plaintext = "Hello, RSA from iOS!".data(using: .utf8)!
            output += "原始数据: \(String(data: plaintext, encoding: .utf8)!)\n"
            
            if let encrypted = CryptoLib.rsaEncrypt(publicKey: rsaKeyPair.publicKey, plaintext: plaintext) {
                output += "加密后 (Base64): \(encrypted.base64EncodedString())\n"
                
                if let decrypted = CryptoLib.rsaDecrypt(privateKey: rsaKeyPair.privateKey, ciphertext: encrypted) {
                    output += "解密后: \(String(data: decrypted, encoding: .utf8)!)\n\n"
                } else {
                    output += "解密失败\n\n"
                }
            } else {
                output += "加密失败\n\n"
            }
        } else {
            output += "RSA 密钥对生成失败\n\n"
        }
        
        // AES-GCM 加解密示例
        output += "=== AES-GCM 加解密示例 ===\n"
        
        if let aesKey = CryptoLib.generateAESKey() {
            output += "AES-256 密钥生成成功\n"
            output += "密钥 (Base64): \(aesKey.base64EncodedString())\n\n"
            
            let plaintext = "Hello, AES-GCM from iOS!".data(using: .utf8)!
            output += "原始数据: \(String(data: plaintext, encoding: .utf8)!)\n"
            
            if let encryptedData = CryptoLib.aesGCMEncrypt(key: aesKey, plaintext: plaintext) {
                output += "密文 (Base64): \(encryptedData.ciphertext)\n"
                output += "Nonce (Base64): \(encryptedData.nonce)\n"
                
                if let decrypted = CryptoLib.aesGCMDecrypt(key: aesKey, encryptedData: encryptedData) {
                    output += "解密后: \(String(data: decrypted, encoding: .utf8)!)\n\n"
                } else {
                    output += "解密失败\n\n"
                }
            } else {
                output += "加密失败\n\n"
            }
        } else {
            output += "AES 密钥生成失败\n\n"
        }
        
        output += "库版本: \(CryptoLib.getVersion())\n"
        
        textView.text = output
    }
}