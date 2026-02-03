package crypto

/*
#cgo windows LDFLAGS: -L. -lcrypto_lib -lbcrypt -lntdll -ladvapi32 -lws2_32 -luserenv
#cgo darwin,amd64 LDFLAGS: -L. -lcrypto_lib -Wl,-rpath,.
#cgo darwin,arm64 LDFLAGS: -L. -lcrypto_lib -Wl,-rpath,.
#cgo linux LDFLAGS: -L. -lcrypto_lib
#cgo CFLAGS: -I.

#include "crypto.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// KeyPair represents an RSA key pair
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// EncryptedData represents AES-GCM encrypted data
type EncryptedData struct {
	Ciphertext string
	Nonce      string
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit length
func GenerateRSAKeyPair(bits int) (*KeyPair, error) {
	cKeyPair := C.crypto_generate_rsa_keypair(C.int(bits))
	if cKeyPair == nil {
		return nil, fmt.Errorf("failed to generate RSA key pair")
	}
	defer C.crypto_free_keypair(cKeyPair)

	publicKey := C.GoString(cKeyPair.public_key)
	privateKey := C.GoString(cKeyPair.private_key)

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// RSAEncrypt encrypts data using RSA public key
func RSAEncrypt(publicKey string, plaintext []byte) ([]byte, error) {
	cPublicKey := C.CString(publicKey)
	defer C.free(unsafe.Pointer(cPublicKey))

	var outLen C.size_t

	cResult := C.crypto_rsa_encrypt(
		cPublicKey,
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		C.size_t(len(plaintext)),
		&outLen,
	)

	if cResult == nil {
		return nil, fmt.Errorf("RSA encryption failed")
	}
	defer C.crypto_free_byte_array(cResult)

	result := C.GoBytes(unsafe.Pointer(cResult.data), C.int(outLen))
	return result, nil
}

// RSADecrypt decrypts data using RSA private key
func RSADecrypt(privateKey string, ciphertext []byte) ([]byte, error) {
	cPrivateKey := C.CString(privateKey)
	defer C.free(unsafe.Pointer(cPrivateKey))

	var outLen C.size_t

	cResult := C.crypto_rsa_decrypt(
		cPrivateKey,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.size_t(len(ciphertext)),
		&outLen,
	)

	if cResult == nil {
		return nil, fmt.Errorf("RSA decryption failed")
	}
	defer C.crypto_free_byte_array(cResult)

	result := C.GoBytes(unsafe.Pointer(cResult.data), C.int(outLen))
	return result, nil
}

// GenerateAESKey generates a new AES-256 key
func GenerateAESKey() ([]byte, error) {
	var outLen C.size_t

	cResult := C.crypto_generate_aes_key(&outLen)
	if cResult == nil {
		return nil, fmt.Errorf("failed to generate AES key")
	}
	defer C.crypto_free_byte_array(cResult)

	result := C.GoBytes(unsafe.Pointer(cResult.data), C.int(outLen))
	return result, nil
}

// AESGCMEncrypt encrypts data using AES-256-GCM
func AESGCMEncrypt(key []byte, plaintext []byte) (*EncryptedData, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes")
	}

	cResult := C.crypto_aes_gcm_encrypt(
		(*C.uchar)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		C.size_t(len(plaintext)),
	)

	if cResult == nil {
		return nil, fmt.Errorf("AES-GCM encryption failed")
	}
	defer C.crypto_free_encrypted_data(cResult)

	return &EncryptedData{
		Ciphertext: C.GoString(cResult.ciphertext),
		Nonce:      C.GoString(cResult.nonce),
	}, nil
}

// AESGCMDecrypt decrypts data using AES-256-GCM
func AESGCMDecrypt(key []byte, encrypted *EncryptedData) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes")
	}

	cCiphertext := C.CString(encrypted.Ciphertext)
	cNonce := C.CString(encrypted.Nonce)
	defer C.free(unsafe.Pointer(cCiphertext))
	defer C.free(unsafe.Pointer(cNonce))

	cEncrypted := &C.struct_CEncryptedData{
		ciphertext: cCiphertext,
		nonce:      cNonce,
	}

	var outLen C.size_t

	cResult := C.crypto_aes_gcm_decrypt(
		(*C.uchar)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		cEncrypted,
		&outLen,
	)

	if cResult == nil {
		return nil, fmt.Errorf("AES-GCM decryption failed")
	}
	defer C.crypto_free_byte_array(cResult)

	result := C.GoBytes(unsafe.Pointer(cResult.data), C.int(outLen))
	return result, nil
}

// GetVersion returns the library version
func GetVersion() string {
	cVersion := C.crypto_get_version()
	defer C.free(unsafe.Pointer(cVersion))
	return C.GoString(cVersion)
}

// ECCGenerateKey generates a new ECC key pair (secp256k1)
func ECCGenerateKey() (*KeyPair, error) {
	cKeyPair := C.crypto_ecc_generate_key()
	if cKeyPair == nil {
		return nil, fmt.Errorf("failed to generate ECC key pair")
	}
	defer C.crypto_free_keypair(cKeyPair)

	publicKey := C.GoString(cKeyPair.public_key)
	privateKey := C.GoString(cKeyPair.private_key)

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// ECCSign signs a message using the private key
// Note: message must be a 32-byte hash (digest), not the original message
func ECCSign(message []byte, privateKey string) ([]byte, error) {
	cPrivateKey := C.CString(privateKey)
	defer C.free(unsafe.Pointer(cPrivateKey))

	var outLen C.size_t

	cResult := C.crypto_ecc_sign(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		cPrivateKey,
		&outLen,
	)

	if cResult == nil {
		return nil, fmt.Errorf("ECC signing failed")
	}
	defer C.crypto_free_byte_array(cResult)

	result := C.GoBytes(unsafe.Pointer(cResult.data), C.int(outLen))
	return result, nil
}

// ECCVerify verifies a signature using the public key
// Note: message must be a 32-byte hash (digest), not the original message
func ECCVerify(message []byte, signature []byte, publicKey string) (bool, error) {
	cPublicKey := C.CString(publicKey)
	defer C.free(unsafe.Pointer(cPublicKey))

	verifyResult := C.crypto_ecc_verify(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		cPublicKey,
	)

	return verifyResult == 1, nil
}

// ECCGetAddress derives an Ethereum address from a public key
func ECCGetAddress(publicKey string) ([]byte, error) {
	cPublicKey := C.CString(publicKey)
	defer C.free(unsafe.Pointer(cPublicKey))

	var outLen C.size_t

	cResult := C.crypto_ecc_get_address(cPublicKey, &outLen)
	if cResult == nil {
		return nil, fmt.Errorf("failed to get address from public key")
	}
	defer C.crypto_free_byte_array(cResult)

	result := C.GoBytes(unsafe.Pointer(cResult.data), C.int(outLen))
	return result, nil
}

// ECCBase58Encode encodes data to Base58
func ECCBase58Encode(data []byte) string {
	cResult := C.crypto_ecc_base58_encode(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
	)
	defer C.free(unsafe.Pointer(cResult))

	return C.GoString(cResult)
}

// ECCBase58Decode decodes Base58 encoded data
func ECCBase58Decode(encoded string) ([]byte, error) {
	cEncoded := C.CString(encoded)
	defer C.free(unsafe.Pointer(cEncoded))

	var outLen C.size_t

	cResult := C.crypto_ecc_base58_decode(cEncoded, &outLen)
	if cResult == nil {
		return nil, fmt.Errorf("failed to decode Base58")
	}
	defer C.crypto_free_byte_array(cResult)

	result := C.GoBytes(unsafe.Pointer(cResult.data), C.int(outLen))
	return result, nil
}

// ECCGetKeyBySeedAndPath derives a key pair from a seed and BIP32 derivation path
// seed: seed string for wallet derivation
// path: derivation path string, e.g., "m/44'/60'/0'/0/0"
func ECCGetKeyBySeedAndPath(seed string, path string) (*KeyPair, error) {
	cSeed := C.CString(seed)
	defer C.free(unsafe.Pointer(cSeed))

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cKeyPair := C.crypto_ecc_get_key_by_seed_and_path(cSeed, cPath)
	if cKeyPair == nil {
		return nil, fmt.Errorf("failed to derive key from seed and path")
	}
	defer C.crypto_free_keypair(cKeyPair)

	publicKey := C.GoString(cKeyPair.public_key)
	privateKey := C.GoString(cKeyPair.private_key)

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}