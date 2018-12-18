package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math"
	"math/bits"
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
// key is repeated circularly, as for Challenge 5
func xor(text, key []byte) []byte {
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

func deviation(f, g []float32) float64 {
	if len(f) != asciiLimit || len(g) != asciiLimit {
		panic("frequency slice has length != asciiLimit")
	}
	var dev float64
	for c := range f {
		diff := float64(f[c]) - float64(g[c])
		dev += diff * diff
	}
	return dev
}

func scoreEnglish(text []byte) float64 {
	return -deviation(englishFreqs, frequencies(text))
}

func decryptSingleXor(cypher []byte) []byte {
	var plain []byte
	maxScore := math.Inf(-1)
	for i := 0; i < 256; i++ {
		text := xor(cypher, []byte{byte(i)})
		s := scoreEnglish(text)
		if s > maxScore {
			maxScore = s
			plain = text
		}
	}
	return plain
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

func decryptVigenereSize(cypher []byte, keysize int) []byte {
	plain := make([]byte, len(cypher))
	var buf []byte
	for offset := 0; offset < keysize; offset++ {
		buf = buf[0:0]
		for i := offset; i < len(cypher); i += keysize {
			buf = append(buf, cypher[i])
		}
		buf = decryptSingleXor(buf)
		for i := range buf {
			plain[offset+i*keysize] = buf[i]
		}
	}
	return plain
}

func decryptVigenere(cypher []byte) (plain, key []byte) {
	if len(cypher) < 1024 {
		panic("decryptVigenere: cyphertext too short.")
	}

	score1 := scoreEnglish(decryptSingleXor(cypher[0:asciiLimit]))
	log.Printf("score1: %f\n", score1)

	score2 := math.Inf(-1)
	keysize2 := 0
	for ks := 2; ks <= 20; ks++ {
		buf := make([]byte, 0, asciiLimit)
		for i := 0; i < len(cypher); i += ks {
			buf = append(buf, cypher[i])
			if len(buf) == cap(buf) {
				break
			}
		}
		score := scoreEnglish(decryptSingleXor(buf))
		if score > score2 {
			score2 = score
			keysize2 = ks
		}
	}
	log.Printf("score2: %f\n", score2)

	minDist := math.Inf(1)
	keysize3 := 0
	for ks := 21; ks <= 40; ks++ {
		dist := (editDistPerBit(cypher[0:ks], cypher[ks:ks*2]) + editDistPerBit(cypher[ks*2:ks*3], cypher[ks*3:ks*4])) / 2
		if dist < minDist {
			minDist = dist
			keysize3 = ks
		}
	}
	score3 := scoreEnglish(decryptVigenereSize(cypher, keysize3))
	log.Printf("score3: %f\n", score3)

	if score1 <= score2 && score1 <= score3 {
		plain = decryptSingleXor(cypher)
		key = xor(cypher[0:1], plain[0:1])
		return
	}
	keysize := keysize3
	if score2 <= score3 {
		keysize = keysize2
	}
	plain = decryptVigenereSize(cypher, keysize)
	key = xor(cypher[0:keysize], plain[0:keysize])
	return
}
