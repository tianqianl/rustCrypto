package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"unsafe"
	crypto2 "crypto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-ethereum-hdwallet"
)

/*
#cgo windows LDFLAGS: -L./crypto -lcrypto_lib -lbcrypt -lntdll -ladvapi32 -lws2_32 -luserenv
#cgo darwin,amd64 LDFLAGS: -L./crypto -lcrypto_lib -Wl,-rpath,./crypto
#cgo darwin,arm64 LDFLAGS: -L./crypto -lcrypto_lib -Wl,-rpath,./crypto
#cgo linux LDFLAGS: -L./crypto -lcrypto_lib
#cgo CFLAGS: -I./crypto

#include "crypto.h"
#include <stdlib.h>
*/
import "C"

// 辅助函数：生成 ECC 密钥对
func GenerateKey() (string, string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", "", err
	}
	pubKey := privateKey.Public().(*ecdsa.PublicKey)
	priKeyBytes := crypto.FromECDSA(privateKey)
	return base58.Encode(priKeyBytes), base58.Encode(crypto.FromECDSAPub(pubKey)), nil
}

// 辅助函数：通过种子和路径生成密钥
func GetKeyBySeedAndPath(seed, pathStr string) (string, string, error) {
	wallet, err := hdwallet.NewFromSeed([]byte(seed))
	if err != nil {
		return "", "", err
	}
	path := hdwallet.MustParseDerivationPath(pathStr)
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", "", err
	}
	priKeyByte, err := wallet.PrivateKeyBytes(account)
	if err != nil {
		return "", "", err
	}
	publicKeyByte, err := wallet.PublicKeyBytes(account)
	if err != nil {
		return "", "", err
	}
	return base58.Encode(priKeyByte), base58.Encode(publicKeyByte), nil
}

// 辅助函数：签名
// 注意：传入的 src 必须是 32 字节的哈希值，不是原始消息
func Sign(src []byte, priKey *ecdsa.PrivateKey) ([]byte, error) {
	var ops crypto2.SignerOpts
	return priKey.Sign(rand.Reader, src, ops)
}

// 辅助函数：验证签名
func VerifySign(message, signature []byte, pubKeyStr string) (bool, error) {
	pubKeyByte := base58.Decode(pubKeyStr)

	// 如果是压缩公钥，先转换为未压缩格式
	if len(pubKeyByte) == 33 && (pubKeyByte[0] == 0x02 || pubKeyByte[0] == 0x03) {
		fmt.Printf("  [调试] 检测到压缩公钥，进行转换...\n")
		uncompressed, err := decompressPublicKey(pubKeyByte)
		if err != nil {
			return false, fmt.Errorf("failed to decompress public key: %v", err)
		}
		pubKeyByte = uncompressed
		fmt.Printf("  [调试] 转换后公钥长度: %d 字节\n", len(pubKeyByte))
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyByte)
	if err != nil {
		return false, err
	}
	var esig struct {
		R, S *big.Int
	}
	if _, err = asn1.Unmarshal(signature, &esig); err != nil {
		return false, err
	}

	// message 参数已经是 32 字节的哈希值，直接验证
	result := ecdsa.Verify(pubKey, message, esig.R, esig.S)
	
	return result, nil
}

// 辅助函数：获取地址
func GetAddressByPubKeyStr(pubKeyStr string) ([]byte, error) {
	pubKeyByte := base58.Decode(pubKeyStr)
	pubKey, err := crypto.UnmarshalPubkey(pubKeyByte)
	if err != nil {
		return nil, err
	}
	return crypto.PubkeyToAddress(*pubKey).Bytes(), nil
}

// 辅助函数：将压缩格式的公钥转换为未压缩格式
func decompressPublicKey(compressedPubKey []byte) ([]byte, error) {
	if len(compressedPubKey) == 65 && compressedPubKey[0] == 0x04 {
		// 已经是未压缩格式，直接返回
		return compressedPubKey, nil
	}

	if len(compressedPubKey) != 33 {
		return nil, fmt.Errorf("invalid compressed public key length: %d", len(compressedPubKey))
	}

	// 使用 btcd 的 secp256k1 库解压缩公钥
	pubKey, err := btcec.ParsePubKey(compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse compressed public key: %v", err)
	}

	// 序列化为未压缩格式
	uncompressed := pubKey.SerializeUncompressed()
	return uncompressed, nil
}

// 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Println("=== Rust ECC FFI 验证脚本 ===\n")

	allPassed := true

	// 测试1: 生成 ECC 密钥对
	fmt.Println("测试 1: 生成 ECC 密钥对")
	if !testGenerateKey() {
		allPassed = false
	}
	fmt.Println()

	// 测试2: 通过种子和路径生成密钥
	fmt.Println("测试 2: 通过种子和路径生成密钥")
	if !testGetKeyBySeedAndPath() {
		allPassed = false
	}
	fmt.Println()

	// 测试3: 签名和验证
	fmt.Println("测试 3: 签名和验证")
	if !testSignAndVerify() {
		allPassed = false
	}
	fmt.Println()

	// 测试4: 获取地址
	fmt.Println("测试 4: 获取地址")
	if !testGetAddress() {
		allPassed = false
	}
	fmt.Println()

	// 测试5: Base58 编码/解码
	fmt.Println("测试 5: Base58 编码/解码")
	if !testBase58() {
		allPassed = false
	}
	fmt.Println()

	// 总结
	if allPassed {
		fmt.Println("✅ 所有测试通过！Rust ECC 迁移正确。")
		os.Exit(0)
	} else {
		fmt.Println("❌ 部分测试失败！请检查 Rust ECC 实现。")
		os.Exit(1)
	}
}

// 测试生成密钥对
func testGenerateKey() bool {
	fmt.Println("  [Go 实现] 生成密钥对")
	goPriKey, goPubKey, err := GenerateKey()
	if err != nil {
		fmt.Printf("  ❌ Go 生成密钥对失败: %v\n", err)
		return false
	}
	fmt.Printf("  ✓ Go 私钥 (Base58): %s\n", goPriKey)
	fmt.Printf("  ✓ Go 公钥 (Base58): %s\n", goPubKey)

	// 添加调试信息
	goPubKeyBytes := base58.Decode(goPubKey)
	fmt.Printf("  [调试] Go 公钥长度: %d 字节\n", len(goPubKeyBytes))
	if len(goPubKeyBytes) > 0 {
		fmt.Printf("  [调试] Go 公钥第一个字节: 0x%02x\n", goPubKeyBytes[0])
		fmt.Printf("  [调试] Go 公钥前20字节 (hex): %s\n", hex.EncodeToString(goPubKeyBytes[:min(20, len(goPubKeyBytes))]))
	}

	fmt.Println("  [Rust 实现] 生成密钥对")
	rustKeyPair := C.crypto_ecc_generate_key()
	if rustKeyPair == nil {
		fmt.Println("  ❌ Rust 生成密钥对失败")
		return false
	}
	defer C.crypto_free_keypair(rustKeyPair)

	rustPriKey := C.GoString(rustKeyPair.private_key)
	rustPubKey := C.GoString(rustKeyPair.public_key)
	fmt.Printf("  ✓ Rust 私钥 (Base58): %s\n", rustPriKey)
	fmt.Printf("  ✓ Rust 公钥 (Base58): %s\n", rustPubKey)

	// 验证密钥格式
	fmt.Println("  [验证] 检查密钥格式")
	if len(rustPriKey) == 0 || len(rustPubKey) == 0 {
		fmt.Println("  ❌ Rust 密钥为空")
		return false
	}

	// 验证 Rust 生成的公钥可以转换为有效的 Ethereum 公钥
	rustPubKeyBytes := base58.Decode(rustPubKey)
	fmt.Printf("  [调试] Rust 公钥长度: %d 字节\n", len(rustPubKeyBytes))
	if len(rustPubKeyBytes) > 0 {
		fmt.Printf("  [调试] Rust 公钥第一个字节: 0x%02x\n", rustPubKeyBytes[0])
		fmt.Printf("  [调试] Rust 公钥前20字节 (hex): %s\n", hex.EncodeToString(rustPubKeyBytes[:min(20, len(rustPubKeyBytes))]))
	}

	// 尝试将压缩公钥转换为未压缩格式
	uncompressedPubKey, err := decompressPublicKey(rustPubKeyBytes)
	if err != nil {
		fmt.Printf("  ❌ 无法转换 Rust 公钥格式: %v\n", err)
		return false
	}
	fmt.Printf("  [调试] 转换后公钥长度: %d 字节\n", len(uncompressedPubKey))
	fmt.Printf("  [调试] 转换后公钥第一个字节: 0x%02x\n", uncompressedPubKey[0])

	_, err = crypto.UnmarshalPubkey(uncompressedPubKey)
	if err != nil {
		fmt.Printf("  ❌ 转换后的公钥格式无效: %v\n", err)
		return false
	}
	fmt.Println("  ✓ Rust 公钥格式有效（已转换为未压缩格式）")

	// 验证 Rust 生成的私钥可以转换为有效的 Ethereum 私钥
	rustPriKeyBytes := base58.Decode(rustPriKey)
	_, err = crypto.ToECDSA(rustPriKeyBytes)
	if err != nil {
		fmt.Printf("  ❌ Rust 私钥格式无效: %v\n", err)
		return false
	}
	fmt.Println("  ✓ Rust 私钥格式有效")

	return true
}

// 测试通过种子和路径生成密钥
func testGetKeyBySeedAndPath() bool {
	seed := "test seed 1234567890"
	path := "m/44'/60'/0'/0/0"

	fmt.Printf("  [Go 实现] 通过种子和路径生成密钥 (seed: %s, path: %s)\n", seed, path)
	goPriKey, goPubKey, err := GetKeyBySeedAndPath(seed, path)
	if err != nil {
		fmt.Printf("  ❌ Go 生成密钥失败: %v\n", err)
		return false
	}
	fmt.Printf("  ✓ Go 私钥 (Base58): %s\n", goPriKey)
	fmt.Printf("  ✓ Go 公钥 (Base58): %s\n", goPubKey)

	fmt.Println("  [Rust 实现] 通过种子和路径生成密钥...")
	cSeed := C.CString(seed)
	defer C.free(unsafe.Pointer(cSeed))
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	rustKeyPair := C.crypto_ecc_get_key_by_seed_and_path(cSeed, cPath)
	if rustKeyPair == nil {
		fmt.Println("  ❌ Rust 生成密钥失败")
		return false
	}
	defer C.crypto_free_keypair(rustKeyPair)

	rustPriKey := C.GoString(rustKeyPair.private_key)
	rustPubKey := C.GoString(rustKeyPair.public_key)
	fmt.Printf("  ✓ Rust 私钥 (Base58): %s\n", rustPriKey)
	fmt.Printf("  ✓ Rust 公钥 (Base58): %s\n", rustPubKey)

	// 验证 Go 和 Rust 生成的密钥应该相同
	fmt.Println("  [验证] 对比 Go 和 Rust 生成的密钥")
	if goPriKey != rustPriKey || goPubKey != rustPubKey {
		fmt.Println("  ❌ Go 和 Rust 生成的密钥不一致")
		fmt.Printf("     Go 私钥: %s\n", goPriKey)
		fmt.Printf("     Rust 私钥: %s\n", rustPriKey)
		fmt.Printf("     Go 公钥: %s\n", goPubKey)
		fmt.Printf("     Rust 公钥: %s\n", rustPubKey)
		return false
	}
	fmt.Println("  ✓ Go 和 Rust 生成的密钥一致")

	return true
}

// 测试签名和验证
func testSignAndVerify() bool {
	message := []byte("Hello, Rust ECC FFI!")
	fmt.Printf("  测试消息: %s\n", string(message))
	
	// 对消息进行 SHA256 哈希
	hash := sha256.Sum256(message)
	fmt.Printf("  消息哈希: %s\n", hex.EncodeToString(hash[:]))

	// 使用 Rust 生成的密钥进行签名
	fmt.Println("  [Rust 实现] 生成密钥对")
	rustKeyPair := C.crypto_ecc_generate_key()
	if rustKeyPair == nil {
		fmt.Println("  ❌ Rust 生成密钥对失败")
		return false
	}
	defer C.crypto_free_keypair(rustKeyPair)

	rustPriKey := C.GoString(rustKeyPair.private_key)
	rustPubKey := C.GoString(rustKeyPair.public_key)

	// Rust 签名 - 传入哈希值而不是原始消息
	fmt.Println("  [Rust 实现] 签名")
	var rustSigLen C.size_t
	rustSig := C.crypto_ecc_sign(
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		C.size_t(len(hash)),
		C.CString(rustPriKey),
		&rustSigLen,
	)
	if rustSig == nil {
		fmt.Println("  ❌ Rust 签名失败")
		return false
	}
	defer C.crypto_free_byte_array(rustSig)

	rustSigBytes := C.GoBytes(unsafe.Pointer(rustSig.data), C.int(rustSigLen))
	fmt.Printf("  ✓ Rust 签名长度: %d 字节\n", len(rustSigBytes))
	fmt.Printf("  ✓ Rust 签名 (hex): %s\n", hex.EncodeToString(rustSigBytes)[:40])

	// Rust 验证 - 传入哈希值而不是原始消息
	fmt.Println("  [Rust 实现] 验证签名...")
	verifyResult := C.crypto_ecc_verify(
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		C.size_t(len(hash)),
		(*C.uchar)(unsafe.Pointer(&rustSigBytes[0])),
		C.size_t(len(rustSigBytes)),
		C.CString(rustPubKey),
	)
	if verifyResult != 1 {
		fmt.Println("  ❌ Rust 验证签名失败")
		return false
	}
	fmt.Println("  ✓ Rust 验证签名成功")

	// 使用 Go 实现验证 Rust 的签名 - 传入哈希值
	fmt.Println("  [Go 实现] 验证 Rust 的签名")
	verified, err := VerifySign(hash[:], rustSigBytes, rustPubKey)
	if err != nil {
		fmt.Printf("  ❌ Go 验证签名失败: %v\n", err)
		return false
	}
	if !verified {
		fmt.Println("  ❌ Go 验证 Rust 签名失败（签名无效）")
		return false
	}
	fmt.Println("  ✓ Go 验证 Rust 签名成功")

	return true
}

// 测试获取地址
func testGetAddress() bool {
	fmt.Println("  [Go 实现] 生成密钥对")
	_, goPubKey, err := GenerateKey()
	if err != nil {
		fmt.Printf("  ❌ Go 生成密钥对失败: %v\n", err)
		return false
	}

	fmt.Println("  [Go 实现] 获取地址")
	goAddr, err := GetAddressByPubKeyStr(goPubKey)
	if err != nil {
		fmt.Printf("  ❌ Go 获取地址失败: %v\n", err)
		return false
	}
	fmt.Printf("  ✓ Go 地址 (hex): 0x%s\n", hex.EncodeToString(goAddr))

	fmt.Println("  [Rust 实现] 获取地址")
	var rustAddrLen C.size_t
	rustAddr := C.crypto_ecc_get_address(C.CString(goPubKey), &rustAddrLen)
	if rustAddr == nil {
		fmt.Println("  ❌ Rust 获取地址失败")
		return false
	}
	defer C.crypto_free_byte_array(rustAddr)

	rustAddrBytes := C.GoBytes(unsafe.Pointer(rustAddr.data), C.int(rustAddrLen))
	fmt.Printf("  ✓ Rust 地址 (hex): 0x%s\n", hex.EncodeToString(rustAddrBytes))

	// 验证地址是否一致
	fmt.Println("  [验证] 对比地址")
	if hex.EncodeToString(goAddr) != hex.EncodeToString(rustAddrBytes) {
		fmt.Println("  ❌ Go 和 Rust 地址不一致")
		fmt.Printf("     Go 地址: 0x%s\n", hex.EncodeToString(goAddr))
		fmt.Printf("     Rust 地址: 0x%s\n", hex.EncodeToString(rustAddrBytes))
		return false
	}
	fmt.Println("  ✓ Go 和 Rust 地址一致")

	return true
}

// 测试 Base58 编码/解码
func testBase58() bool {
	testData := []byte("Hello, Base58!")
	fmt.Printf("  原始数据: %s\n", string(testData))

	// Rust 编码
	fmt.Println("  [Rust 实现] Base58 编码")
	rustEncoded := C.crypto_ecc_base58_encode(
		(*C.uchar)(unsafe.Pointer(&testData[0])),
		C.size_t(len(testData)),
	)
	defer C.free(unsafe.Pointer(rustEncoded))
	rustEncodedStr := C.GoString(rustEncoded)
	fmt.Printf("  ✓ Rust 编码: %s\n", rustEncodedStr)

	// Rust 解码
	fmt.Println("  [Rust 实现] Base58 解码")
	var rustDecodedLen C.size_t
	rustDecoded := C.crypto_ecc_base58_decode(C.CString(rustEncodedStr), &rustDecodedLen)
	if rustDecoded == nil {
		fmt.Println("  ❌ Rust 解码失败")
		return false
	}
	defer C.crypto_free_byte_array(rustDecoded)

	rustDecodedBytes := C.GoBytes(unsafe.Pointer(rustDecoded.data), C.int(rustDecodedLen))
	fmt.Printf("  ✓ Rust 解码: %s\n", string(rustDecodedBytes))

	// 验证编码/解码
	fmt.Println("  [验证] 对比原始数据和解码数据")
	if string(testData) != string(rustDecodedBytes) {
		fmt.Println("  ❌ 原始数据和解码数据不一致")
		return false
	}
	fmt.Println("  ✓ 原始数据和解码数据一致")

	// 与 Go 实现对比
	fmt.Println("  [Go 实现] Base58 编码")
	goEncoded := base58.Encode(testData)
	fmt.Printf("  ✓ Go 编码: %s\n", goEncoded)

	fmt.Println("  [验证] 对比 Go 和 Rust 编码结果")
	if goEncoded != rustEncodedStr {
		fmt.Println("  ❌ Go 和 Rust 编码结果不一致")
		return false
	}
	fmt.Println("  ✓ Go 和 Rust 编码结果一致")

	return true
}
