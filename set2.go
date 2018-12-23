package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	mathrand "math/rand"
	"strconv"
	"strings"
)

// Challenge 9 (PKCS#7 padding)
// Pad may append to text's underlying array!
func Pad(text []byte, blocksize int) []byte {
	for len(text)%blocksize != 0 {
		text = append(text, '\x04')
	}
	return text
}

func Unpad(text []byte) []byte {
	for len(text) > 0 && text[len(text)-1] == '\x04' {
		text = text[0 : len(text)-1]
	}
	return text
}

// Challenge 10
func EncryptCBC(iv []byte, plain []byte, b cipher.Block) []byte {
	bs := b.BlockSize()
	if len(iv) != bs || len(plain)%bs != 0 {
		panic("EncryptCBC: wrong block size.")
	}
	ciph := make([]byte, len(plain))
	for i := 0; i < len(plain); i += bs {
		b.Encrypt(ciph[i:], Xor(plain[i:i+bs], iv))
		iv = ciph[i : i+bs]
	}
	return ciph
}

func DecryptCBC(iv []byte, ciph []byte, b cipher.Block) []byte {
	bs := b.BlockSize()
	if len(iv) != bs || len(ciph)%bs != 0 {
		panic("EncryptCBC: wrong block size.")
	}
	plain := make([]byte, len(ciph))
	for i := 0; i < len(ciph); i += bs {
		b.Decrypt(plain[i:], ciph[i:])
		copy(plain[i:], Xor(plain[i:i+bs], iv))
		iv = ciph[i : i+bs]
	}
	return plain
}

// Challenge 11
func encryptionOracle11(seed int64) func([]byte) []byte {
	const blocksize = 16
	mathrand.Seed(seed)
	useCBC := mathrand.Intn(10) < 5
	prefix := make([]byte, 5+mathrand.Intn(6))
	suffix := make([]byte, 5+mathrand.Intn(6))
	key := make([]byte, blocksize)
	iv := make([]byte, blocksize)
	mathrand.Read(prefix)
	mathrand.Read(suffix)
	mathrand.Read(key)
	mathrand.Read(iv)
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return func(plain []byte) []byte {
		var msg []byte
		msg = append(msg, prefix...)
		msg = append(msg, plain...)
		msg = append(msg, suffix...)
		msg = Pad(msg, blocksize)
		if useCBC {
			return EncryptCBC(iv, msg, b)
		}
		return EncryptECB(msg, b)
	}
}

// Challenge 12
func encryptionOracle12(seed int64, unknown []byte) func([]byte) []byte {
	const blocksize = 16
	mathrand.Seed(seed)
	key := make([]byte, blocksize)
	mathrand.Read(key)
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return func(prefix []byte) []byte {
		var msg []byte
		msg = append(msg, prefix...)
		msg = append(msg, unknown...)
		return EncryptECB(Pad(msg, blocksize), b)
	}
}

func findBlocksizeECB(encrypt func([]byte) []byte) int {
	prefix := bytes.Repeat([]byte{'A'}, 8)
	for bs := 4; bs <= 128; bs++ {
		ciph := encrypt(prefix)
		if string(ciph[0:bs]) == string(ciph[bs:bs*2]) {
			return bs
		}
		prefix = append(prefix, 'A', 'A')
	}
	return -1
}

/*
with blocksize = 4
unknown:
0123 4567
to recover 0:
AAA0 1234 567-
to recover 1:
AA01 2345 67--
to recover 2:
A012 3456 7---
to recover 3:
0123 4567
now we have 0123
to recover 4:
AAA0 1234
...
*/
func RecoverSuffixECB(encrypt func([]byte) []byte) []byte {
	blocksize := findBlocksizeECB(encrypt)
	suffixLen := len(encrypt(nil))
	if suffixLen%blocksize != 0 {
		panic("decryptSuffixECB: ecnrypt function doesn't agree with blocksize.")
	}
	// We pretend that the unknown suffix starts with Repeat('A', blocksize-1),
	// as it simplifies building the dictionary.
	plain := bytes.Repeat([]byte{'A'}, blocksize-1)
	for b := 0; b < suffixLen; b += blocksize {
		for i := 0; i < blocksize; i++ {
			dict := make(map[string]byte)
			plainBlock := make([]byte, blocksize)
			for c := 0; c < 256; c++ {
				copy(plainBlock[0:blocksize-1], plain[b+i:])
				plainBlock[blocksize-1] = byte(c)
				ciphBlock := encrypt(plainBlock)[0:blocksize]
				dict[string(ciphBlock)] = byte(c)
			}
			prefix := plain[0 : blocksize-i-1] // all 'A's
			ciphBlock := encrypt(prefix)[b : b+blocksize]
			plain = append(plain, dict[string(ciphBlock)])
		}
	}
	return plain[blocksize-1:]
}

// Challenge 13
func profileFor(email string, uid int) string {
	if strings.ContainsAny(email, "&=") {
		panic("profileFor: email contains metacharacters & or =")
	}
	return "email=" + email + "&uid=" + strconv.Itoa(uid) + "&role=user"
}

func profileEncrypter(seed int64) func(email string) []byte {
	const blocksize = 16
	mathrand.Seed(seed)
	key := make([]byte, blocksize)
	mathrand.Read(key)
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	uid := 10 + mathrand.Intn(90) // always two digits, to make it a little bit easier
	return func(email string) []byte {
		msg := []byte(profileFor(email, uid))
		return EncryptECB(Pad(msg, blocksize), b)
	}
}

func profileDecrypter(seed int64) func([]byte) []byte {
	const blocksize = 16
	mathrand.Seed(seed)
	key := make([]byte, blocksize)
	mathrand.Read(key)
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return func(ciph []byte) []byte {
		return Unpad(DecryptECB(ciph, b))
	}
}
