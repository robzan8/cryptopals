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

func DecryptSingleXor(text []byte, score func([]byte) float64) []byte {
	chunkLen := 30
	if len(text) < chunkLen {
		chunkLen = len(text)
	}

	maxScore := math.Inf(-1)
	key := -1
	for i := 0; i < 256; i++ {
		s := score(Xor(text[0:chunkLen], []byte{byte(i)}))
		if s > maxScore {
			maxScore = s
			key = i
		}
	}
	return Xor(text, []byte{byte(key)})
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

const maxKeysize = 40

func editDistKeysize(text []byte, keysize int) float64 {
	var dist, n float64
	for i := 0; i < 4*keysize; i += keysize {
		dist += editDistPerBit(text[i:i+keysize], text[i+keysize:i+keysize*2])
		n += 1
	}
	return dist / n
}

func findVigenereSize(text []byte) int {
	minDist := math.Inf(1)
	keysize := 0
	for ks := 2; ks <= maxKeysize; ks++ {
		dist := editDistKeysize(text, ks)
		if dist < minDist {
			minDist = dist
			keysize = ks
		}
	}
	return keysize
}

func DecryptVigenere(text []byte, score func([]byte) float64) (plain, key []byte) {
	if len(text) < 2*maxKeysize {
		panic("DecryptVigenere: text too short.")
	}
	keysize := findVigenereSize(text)
	plain = make([]byte, len(text))
	var col []byte
	for offset := 0; offset < keysize; offset++ {
		col = col[0:0]
		for i := offset; i < len(text); i += keysize {
			col = append(col, text[i])
		}
		col = DecryptSingleXor(col, score)
		for i := range col {
			plain[offset+i*keysize] = col[i]
		}
	}
	key = Xor(text[0:keysize], plain[0:keysize])
	return
}

// Challenge 7
func DecryptECB(text []byte, c cipher.Block) []byte {
	blocksize := c.BlockSize()
	log.Println(blocksize)
	if len(text)%blocksize != 0 {
		panic("DecryptECB: len(text) is not a multiple of BlockSize.")
	}
	plain := make([]byte, len(text))
	for i := 0; i < len(text); i += blocksize {
		c.Decrypt(plain[i:], text[i:])
	}
	return plain
}

// Challenge 8
func DetectECB(text []byte, blocksize int) bool {
	if len(text)%blocksize != 0 {
		panic("DetectECB: len(text) is not a multiple of blocksize.")
	}
	seen := make(map[string]struct{})
	for i := 0; i < len(text); i += blocksize {
		block := string(text[i : i+blocksize])
		if _, ok := seen[block]; ok {
			return true
		}
		seen[block] = struct{}{}
	}
	return false
}
