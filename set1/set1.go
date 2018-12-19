package cryptopals

import (
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

func DecryptSingleXor(cypher []byte, score func([]byte) float64) []byte {
	var plain []byte
	maxScore := math.Inf(-1)
	for i := 0; i < 256; i++ {
		text := Xor(cypher, []byte{byte(i)})
		s := score(text)
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

func decryptVigenereSize(cypher []byte, score func([]byte) float64, keysize int) (plain, key []byte) {
	plain = make([]byte, len(cypher))
	var buf []byte
	for offset := 0; offset < keysize; offset++ {
		buf = buf[0:0]
		for i := offset; i < len(cypher); i += keysize {
			buf = append(buf, cypher[i])
		}
		buf = DecryptSingleXor(buf, score)
		for i := range buf {
			plain[offset+i*keysize] = buf[i]
		}
	}
	key = Xor(cypher[0:keysize], plain[0:keysize])
	return
}

const maxKeysize = 40

func DecryptVigenere(cypher []byte, score func([]byte) float64) (plain, key []byte) {
	if len(cypher) < maxKeysize*scoreMinLength {
		panic("decryptVigenere: cyphertext too short.")
	}

	const scoreChunckLen = 30
	buf := make([]byte, 0, scoreChunckLen)
	bestScore := math.Inf(-1)
	keysize := 0
	for ks := 1; ks <= maxKeysize; ks++ {
		buf = buf[0:0:scoreChunckLen]
		for i := 0; i < len(cypher); i += ks {
			buf = append(buf, cypher[i])
			if len(buf) == cap(buf) {
				break
			}
		}
		s := score(DecryptSingleXor(buf, score))
		if s > bestScore {
			bestScore = s
			keysize = ks
		}
	}

	/*minDist := math.Inf(1)
	keysize2 := 0
	for ks := 21; ks <= 40; ks++ {
		dist := (editDistPerBit(cypher[0:ks], cypher[ks:ks*2]) + editDistPerBit(cypher[ks:ks*2], cypher[ks*2:ks*3])) / 2
		if dist < minDist {
			minDist = dist
			keysize2 = ks
		}
	}
	bestScore2 := score(decryptVigenereSize(cypher, score, keysize2))*/

	return decryptVigenereSize(cypher, score, keysize)
}
