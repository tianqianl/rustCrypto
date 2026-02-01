package utils

import "github.com/btcsuite/btcutil/base58"

func Base58Encode(msg []byte) string {
	return base58.Encode(msg)
}

func Base58Decode(msg string) []byte {
	return base58.Decode(msg)
}
