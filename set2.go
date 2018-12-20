package cryptopals

import "crypto/cipher"

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
