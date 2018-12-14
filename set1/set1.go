package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
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

// Not sophisticated, but distinguishes english text from random junk.
func isEnglish(text []byte) bool {
	return deviation(englishFreqs, frequencies(text)) <= 0.04
}

func singleXor(text []byte, c byte) []byte {
	return xor(text, []byte{c})
}

func decryptSingleXor(xored []byte) []byte {
	for i := 0; i < 256; i++ {
		text := singleXor(xored, byte(i))
		if isEnglish(text) {
			return text
		}
	}
	return nil
}

// Challenge 5: see func xor
