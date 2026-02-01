package ecc

import (
	crypto2 "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tbzims/ecc/utils"
	"math/big"
)

type Wallets = hdwallet.Wallet

type Account = accounts.Account

func GenerateKey() (string, string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", "", err
	}
	pubKey := privateKey.Public().(*ecdsa.PublicKey)
	priKeyBytes := crypto.FromECDSA(privateKey)
	return utils.Base58Encode(priKeyBytes), utils.Base58Encode(crypto.FromECDSAPub(pubKey)), nil
}

func GetKeyBySeedAndPath(seed, pathStr string) (string, string, error) {
	wallet, err := hdwallet.NewFromSeed([]byte(seed))
	if err != nil {
		return "", "", err
	}
	path := hdwallet.MustParseDerivationPath(pathStr) // "m/44'/60'/0'/0/0"
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
	return utils.Base58Encode(priKeyByte), utils.Base58Encode(publicKeyByte), nil
}

func UnmarshalPrivateKeyByString(key string) (*ecdsa.PrivateKey, error) {
	return crypto.ToECDSA(base58.Decode(key))
}

func SignByPrivateKeyStr(src []byte, pri string) ([]byte, error) {
	priKey, err := crypto.ToECDSA(utils.Base58Decode(pri))
	if err != nil {
		return nil, err
	}
	return Sign(src, priKey)
}

func Sign(src []byte, priKey *ecdsa.PrivateKey) ([]byte, error) {
	var ops crypto2.SignerOpts
	return priKey.Sign(rand.Reader, src, ops)
}

func GetAddressByPubKeyStr(pubKeyStr string) ([]byte, error) {
	pubKey, err := UnmarshalPublicKeyByStr(pubKeyStr)
	if err != nil {
		return nil, err
	}
	return crypto.PubkeyToAddress(*pubKey).Bytes(), nil
}

func UnmarshalPublicKeyByStr(pubKeyStr string) (*ecdsa.PublicKey, error) {
	pubKeyByte := utils.Base58Decode(pubKeyStr)
	return crypto.UnmarshalPubkey(pubKeyByte)
}

func VerifySign(message, signature []byte, pubKeyStr string) (bool, error) {
	//return true
	pubKey, err := UnmarshalPublicKeyByStr(pubKeyStr)
	if err != nil {
		return false, err
	}
	var esig struct {
		R, S *big.Int
	}
	if _, err = asn1.Unmarshal(signature, &esig); err != nil {
		return false, err
	}
	return ecdsa.Verify(pubKey, message, esig.R, esig.S), nil
}
