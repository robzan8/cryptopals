package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	mathrand "math/rand"
)

// Challenge 9 (PKCS#7 padding)
func Pad(text []byte, blocksize int) []byte {
	for len(text)%blocksize != 0 {
		text = append(text, '\x04')
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
func randEncrypter(seed int64) func([]byte) []byte {
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
		plain = append(prefix, plain...)
		plain = append(plain, suffix...)
		plain = Pad(plain, blocksize)
		if useCBC {
			return EncryptCBC(iv, plain, b)
		}
		return EncryptECB(plain, b)
	}
}
