package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

func decodeHex(s string) []byte {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func encodeHex(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func decodeBase64(s string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func encodeBase64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

// Challenge 1
func hexToBase64(s string) string {
	return encodeBase64(decodeHex(s))
}

// Challenge 2
func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor: slices' length mismatch")
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res
}
