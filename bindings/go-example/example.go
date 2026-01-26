package main

import (
	"encoding/base64"
	"fmt"
	"go-example/crypto"
)

func main() {
	fmt.Println("=== RSA 加解密示例 ===")

	// 生成 RSA 密钥对
	keypair, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		panic(err)
	}

	fmt.Println("RSA 密钥对生成成功")
	fmt.Println("公钥:", keypair.PublicKey)
	fmt.Printf("公钥长度: %d 字节\n", len(keypair.PublicKey))
	fmt.Println("私钥:", keypair.PrivateKey)
	fmt.Printf("私钥长度: %d 字节\n", len(keypair.PrivateKey))

	// RSA 加密
	plaintext := []byte("Hello, RSA from Go!")
	fmt.Printf("\n原始数据: %s\n", string(plaintext))

	encrypted, err := crypto.RSAEncrypt(keypair.PublicKey, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("加密后 (Base64): %s\n", base64.StdEncoding.EncodeToString(encrypted))

	// RSA 解密
	decrypted, err := crypto.RSADecrypt(keypair.PrivateKey, encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("解密后: %s\n", string(decrypted))

	fmt.Println("\n=== AES-GCM 加解密示例 ===")

	// 生成 AES 密钥
	aesKey, err := crypto.GenerateAESKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("AES-256 密钥生成成功")
	fmt.Printf("密钥 (Base64): %s\n", base64.StdEncoding.EncodeToString(aesKey))

	// AES-GCM 加密
	plaintext2 := []byte("Hello, AES-GCM from Go!")
	fmt.Printf("\n原始数据: %s\n", string(plaintext2))

	encryptedData, err := crypto.AESGCMEncrypt(aesKey, plaintext2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("密文 (Base64): %s\n", encryptedData.Ciphertext)
	fmt.Printf("Nonce (Base64): %s\n", encryptedData.Nonce)
	fmt.Printf("Tag (Base64): %s\n", encryptedData.Tag)

	// AES-GCM 解密
	decrypted2, err := crypto.AESGCMDecrypt(aesKey, encryptedData)
	if err != nil {
		panic(err)
	}
	fmt.Printf("解密后: %s\n", string(decrypted2))

	fmt.Printf("\n库版本: %s\n", crypto.GetVersion())
}
