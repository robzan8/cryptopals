package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
)

// Challenge 1
func hexToBase64(hs string) (string, error) {
	bytes, err := hex.DecodeString(hs)
	if err != nil {
		return "", fmt.Errorf("hetToBase64 error: %s", err)
	}
	log.Println(string(bytes))
	return base64.StdEncoding.EncodeToString(bytes), nil
}
