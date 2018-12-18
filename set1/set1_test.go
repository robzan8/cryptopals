package cryptopals

import (
	"bufio"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

// Challenge 1
func TestHexToBase64(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	res := hexToBase64(in)
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if res != expected {
		t.Fatalf("hexToBase64 failed Challange 1. Expected %s, got %s.\n", expected, res)
	}
	t.Log(string(decodeHex(in)))
}

// Challenge 2
func TestXor(t *testing.T) {
	a := decodeHex("1c0111001f010100061a024b53535009181c")
	t.Log(string(a))
	b := decodeHex("686974207468652062756c6c277320657965")
	t.Log(string(b))
	res := encodeHex(xor(a, b))
	expected := "746865206b696420646f6e277420706c6179"
	if res != expected {
		t.Fatalf("xor failed Challange 2. Expected %s, got %s.\n", expected, res)
	}
	t.Log(string(decodeHex(res)))
}

// Challenge 3

func TestFrequencies(t *testing.T) {
	var sum float32
	for _, f := range englishFreqs {
		sum += f
	}
	if sum < 0.9 || sum > 1.1 {
		t.Fatal("Sum of frequencies is not 1.")
	}
	freqs := frequencies([]byte("abcc"))
	expected := make([]float32, asciiLimit)
	expected['a'] = 0.25
	expected['b'] = 0.25
	expected['c'] = 0.5
	if !reflect.DeepEqual(freqs, expected) {
		t.Fatalf("frequencies(\"abcc\") wrong; expected %v, got %v.\n", expected, freqs)
	}
}

func TestDeviation(t *testing.T) {
	f := frequencies([]byte("56i65r5rcu4ex53wwyvv8675v56echctdrh4zw"))
	if deviation(f, f) != 0 {
		t.Fatal("deviation(f, f) is not zero.")
	}
	f, g := make([]float32, asciiLimit), make([]float32, asciiLimit)
	f['a'], f['b'], f['c'] = 1, 1, 0.5
	g['b'], g['c'], g['d'] = 1, 1, 0
	dev := deviation(f, g)
	expected := 1 + 0 + 0.25 + 0
	if dev != expected {
		log.Fatalf("Wrong deviation({a:1, b:1, c:0.5}, {b:1, c:1, d:0}); expected %f, got %f.\n", expected, dev)
	}
	eng := "Seed uses the provided seed value to initialize the default Source to a deterministic state. If Seed is not called, the generator behaves as if seeded by Seed(1). Seed values that have the same remainder when divided by 2^31-1 generate the same pseudo-random sequence. Seed, unlike the Rand.Seed method, is safe for concurrent use."
	t.Log(deviation(englishFreqs, frequencies([]byte(eng))))
	r := make([]byte, 1024)
	rand.Seed(666)
	rand.Read(r)
	t.Log(deviation(englishFreqs, frequencies(r)))
}

func isEnglish(text []byte) bool {
	return scoreEnglish(text) >= -0.035
}

func TestChallenge3(t *testing.T) {
	text := decryptSingleXor(decodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	t.Log(string(text))
	t.Log(scoreEnglish(text))
}

// Challenge 4
func TestChallenge4(t *testing.T) {
	file, err := os.Open("challenge-data/4.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	maxScore := math.Inf(-1)
	var plain []byte
	for scanner.Scan() {
		line := decryptSingleXor(decodeHex(scanner.Text()))
		s := scoreEnglish(line)
		if s > maxScore {
			maxScore = s
			plain = line
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}

func BenchmarkChallenge4(b *testing.B) {
	buf := make([]byte, 100)
	rand.Seed(666)
	for i := 0; i < b.N; i++ {
		rand.Read(buf)
		decryptSingleXor(buf)
	}
}

// Challenge 5
func TestRepeatingXor(t *testing.T) {
	text := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	encrypted := encodeHex(xor(text, []byte("ICE")))
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if encrypted != expected {
		t.Fatalf("Challenge 5 failed; expected:\n%s\ngot:\n%s\n", expected, encrypted)
	}
}

// Challenge 6
func TestEditDistance(t *testing.T) {
	dist := editDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if dist != 37 {
		t.Fatalf("Challenge 6 fail: expected editDistance == 37, got: %d\n.", dist)
	}
	text := []byte("Make sure your code agrees before you proceed")
	dist1 := editDistPerBit(text[0:20], text[20:40])
	dist2 := editDistPerBit(xor(text[0:20], []byte("wonderfulwonderfulwo")), xor(text[20:40], []byte("erfulwonderfulwonder")))
	if dist1 >= dist2 {
		t.Fatalf("editDistPerBit: unexpected result")
	}
	t.Log(dist1, dist2)
}

func TestVigenere(t *testing.T) {
	cypher, err := ioutil.ReadFile("challenge-data/6.txt")
	if err != nil {
		t.Fatal(err)
	}
	cypher = decodeBase64(string(cypher))
	_, key := decryptVigenere(cypher)
	t.Log(string(key))
}
