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