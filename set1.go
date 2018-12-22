package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math"
	"math/bits"
)

func DecodeHex(s string) []byte {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func EncodeHex(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func DecodeBase64(s string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func EncodeBase64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

// Challenge 1
func hexToBase64(s string) string {
	return EncodeBase64(DecodeHex(s))
}

// Challenge 2

// key is repeated circularly, as for Challenge 5.
func Xor(text, key []byte) []byte {
	if len(key) == 0 {
		panic("xor: key can't be empty")
	}
	res := make([]byte, len(text))
	if len(key) == 1 {
		// Fast path.
		k := key[0]
		for i := range text {
			res[i] = text[i] ^ k
		}
		return res
	}
	for i := range text {
		res[i] = text[i] ^ key[i%len(key)]
	}
	return res
}

// Challenge 3

const asciiLimit = 128

// []float32 maps ascii characteds to frequencies (map was slow).
func frequencies(chars []byte) []float32 {
	if len(chars) == 0 {
		panic("Can't compute character frequencies on empty slice.")
	}
	freqs := make([]float32, asciiLimit)
	for _, c := range chars {
		if c < asciiLimit {
			freqs[c] += 1
		}
	}
	for c := range freqs {
		freqs[c] /= float32(len(chars))
	}
	return freqs
}

func freqsFromFile(name string) []float32 {
	chars, err := ioutil.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return frequencies(chars)
}

var englishFreqs = freqsFromFile("english text.txt")

/*func deviation(f, g []float32) float64 {
	if len(f) != asciiLimit || len(g) != asciiLimit {
		panic("frequency slice has length != asciiLimit")
	}
	var dev float64
	for c := range f {
		diff := float64(f[c]) - float64(g[c])
		dev += diff * diff
	}
	return dev
}*/

const scoreMinLength = 6

func ScoreEnglish(text []byte) float64 {
	if len(text) == 0 {
		panic("scoreEnglish: can't score an empty text.")
	}
	if len(text) < scoreMinLength {
		log.Println("Warning: ScoreEnglish on short text may be noisy.")
	}
	var score float64
	for _, c := range text {
		if c < asciiLimit {
			score += float64(englishFreqs[c])
		}
	}
	return score / float64(len(text))
}

func BreakSingleXor(ciph []byte, score func([]byte) float64) []byte {
	chunkLen := 30
	if len(ciph) < chunkLen {
		chunkLen = len(ciph)
	}

	maxScore := math.Inf(-1)
	key := -1
	for i := 0; i < 256; i++ {
		s := score(Xor(ciph[0:chunkLen], []byte{byte(i)}))
		if s > maxScore {
			maxScore = s
			key = i
		}
	}
	return Xor(ciph, []byte{byte(key)})
}

// Challenge 5: see func xor

// Challenge 6
func editDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("editDistance: length mismatch.")
	}
	var dist int
	for i := range a {
		dist += bits.OnesCount8(a[i] ^ b[i])
	}
	return dist
}

func editDistPerBit(a, b []byte) float64 {
	return float64(editDistance(a, b)) / float64(len(a)*8)
}

func editDistKeysize(text []byte, ks int) float64 {
	var dist, n float64
	for i := ks; i < 100; i += ks {
		dist += editDistPerBit(text[i-ks:i], text[i:i+ks])
		n += 1
	}
	return dist / n
}

const maxKeysize = 40

func findVigenereSize(ciph []byte) int {
	minDist := math.Inf(1)
	keysize := -1
	for ks := 1; ks < maxKeysize; ks++ {
		dist := editDistKeysize(ciph, ks)
		if dist < minDist {
			minDist = dist
			keysize = ks
		}
	}
	return keysize
}

func BreakVigenere(ciph []byte, score func([]byte) float64) (plain, key []byte) {
	if len(ciph) < maxKeysize*scoreMinLength {
		panic("BreakVigenere: cyphertext too short.")
	}
	keysize := findVigenereSize(ciph)
	plain = make([]byte, len(ciph))
	var buf []byte
	for offset := 0; offset < keysize; offset++ {
		buf = buf[0:0]
		for i := offset; i < len(ciph); i += keysize {
			buf = append(buf, ciph[i])
		}
		buf = BreakSingleXor(buf, score)
		for i := range buf {
			plain[offset+i*keysize] = buf[i]
		}
	}
	key = Xor(ciph[0:keysize], plain[0:keysize])
	return
}

// Challenge 7
func DecryptECB(ciph []byte, b cipher.Block) []byte {
	blocksize := b.BlockSize()
	if len(ciph)%blocksize != 0 {
		panic("DecryptECB: len(ciph) is not a multiple of BlockSize.")
	}
	plain := make([]byte, len(ciph))
	for i := 0; i < len(ciph); i += blocksize {
		b.Decrypt(plain[i:], ciph[i:])
	}
	return plain
}

func EncryptECB(plain []byte, b cipher.Block) []byte {
	blocksize := b.BlockSize()
	if len(plain)%blocksize != 0 {
		panic("EncryptECB: len(plain) is not a multiple of BlockSize.")
	}
	ciph := make([]byte, len(plain))
	for i := 0; i < len(plain); i += blocksize {
		b.Encrypt(ciph[i:], plain[i:])
	}
	return ciph
}

// Challenge 8
func DetectECB(ciph []byte, blocksize int) bool {
	if len(ciph)%blocksize != 0 {
		panic("DetectECB: len(ciph) is not a multiple of blocksize.")
	}
	seen := make(map[string]struct{})
	for i := 0; i < len(ciph); i += blocksize {
		block := string(ciph[i : i+blocksize])
		if _, ok := seen[block]; ok {
			return true
		}
		seen[block] = struct{}{}
	}
	return false
}
