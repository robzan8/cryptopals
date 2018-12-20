package cryptopals

import (
	"crypto/aes"
	"testing"
)

// Challenge 9
func TestPad(t *testing.T) {
	text := Pad([]byte("YELLOW SUBMARINE"), 20)
	if string(text) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Fatal("Challenge 9 failed.")
	}
}

// Challenge 10
func TestCBC(t *testing.T) {
	plain := readFile(t, "challenge-data/7_plain.txt")
	plain = Pad(plain, 16)
	iv := []byte("submarine yellow")
	b, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}
	ciph := EncryptCBC(iv, plain, b)
	plain2 := DecryptCBC(iv, ciph, b)
	if string(plain) != string(plain2) {
		t.Fatal("Challenge 10 failed: encrypt/decrypt round trip doesn't work.")
	}

	ciph = DecodeBase64(string(readFile(t, "challenge-data/10.txt")))
	iv = make([]byte, 16)
	plain = DecryptCBC(iv, ciph, b)
	if !isEnglish(plain) {
		t.Fatal("Challenge 10 failed: result is not intelligible.")
	}
	writeFile(t, "challenge-data/10_plain.txt", plain)
}
