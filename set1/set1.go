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
func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor: slices' length mismatch")
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res
}

// Challenge 3

func frequencies(chars []byte) map[byte]float64 {
	if len(chars) == 0 {
		panic("Can't compute character frequencies on empty slice.")
	}
	freqs := make(map[byte]float64)
	for _, c := range chars {
		freqs[c] += 1
	}
	for c, f := range freqs {
		freqs[c] = f / float64(len(chars))
	}
	return freqs
}

func freqsFromFile(name string) map[byte]float64 {
	chars, err := ioutil.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return frequencies(chars)
}

var englishFreqs = freqsFromFile("english text.txt")

func deviation(f, g map[byte]float64) float64 {
	chars := make(map[byte]struct{})
	for c := range f {
		chars[c] = struct{}{}
	}
	for c := range g {
		chars[c] = struct{}{}
	}
	var dev float64
	for c := range chars {
		diff := f[c] - g[c]
		dev += diff * diff
	}
	return dev
}

// Not sophisticated, but distinguishes english text from random junk.
func isEnglish(text []byte) bool {
	return deviation(englishFreqs, frequencies(text)) <= 0.04
}

func singleXor(text []byte, c byte) []byte {
	res := make([]byte, len(text))
	for i := range text {
		res[i] = text[i] ^ c
	}
	return res
}
