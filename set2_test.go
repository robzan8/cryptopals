package cryptopals

import (
	"crypto/aes"
	mathrand "math/rand"
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

// Challenge 11
func TestChallenge11(t *testing.T) {
	for i := int64(0); i < 20; i++ {
		mathrand.Seed(i)
		useECB := !(mathrand.Intn(10) < 5)
		encrypt := RandEncrypter(i)
		ciph := encrypt(make([]byte, 100))
		if DetectECB(ciph, 16) != useECB {
			t.Fatal("Challenge 11 failed: could not detect ECB/CBC correctly.")
		}
	}
}

// Challenge 12
func TestChallenge12(t *testing.T) {
	unknown := DecodeBase64(
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)
	encrypt := RandEncrypterECB(4687537893121534684, unknown)
	known := RecoverSuffixECB(encrypt)
	if string(known) != string(Pad(unknown, 16)) {
		t.Fatal("Challenge 12 failed: could not recover the suffix.")
	}
	t.Log(string(unknown))
}
