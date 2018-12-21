package cryptopals

import (
	"crypto/aes"
	"io/ioutil"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	text, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func writeFile(t *testing.T, name string, text []byte) {
	t.Helper()
	if err := ioutil.WriteFile(name, text, 0664); err != nil {
		t.Fatal(err)
	}
}

// Challenge 1
func TestHexToBase64(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	res := hexToBase64(in)
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if res != expected {
		t.Fatalf("hexToBase64 failed Challange 1. Expected %s, got %s.\n", expected, res)
	}
	t.Log(string(DecodeHex(in)))
}

// Challenge 2
func TestXor(t *testing.T) {
	a := DecodeHex("1c0111001f010100061a024b53535009181c")
	t.Log(string(a))
	b := DecodeHex("686974207468652062756c6c277320657965")
	t.Log(string(b))
	res := EncodeHex(Xor(a, b))
	expected := "746865206b696420646f6e277420706c6179"
	if res != expected {
		t.Fatalf("xor failed Challange 2. Expected %s, got %s.\n", expected, res)
	}
	t.Log(string(DecodeHex(res)))
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

func TestScoreEnglish(t *testing.T) {
	eng := "Go is an open source programming language that makes it easy to build simple, reliable, and efficient software."
	t.Logf("Score of english text: %f", ScoreEnglish([]byte(eng)))
	r := make([]byte, 128)
	rand.Seed(6654684658386461111)
	rand.Read(r)
	t.Logf("Score of pseudorandom bytes: %f", ScoreEnglish(r))
	xored := Xor([]byte("Go is an open source programming"), []byte("language that makes it"))
	t.Logf("Score of xored text: %f", ScoreEnglish(xored))
}

// English text typically has a score of 0.07
func isEnglish(text []byte) bool {
	return ScoreEnglish(text) >= 0.045
}

func TestChallenge3(t *testing.T) {
	ciph := DecodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	plain := DecryptSingleXor(ciph, ScoreEnglish)
	if !isEnglish(plain) {
		t.Fatal("Challenge 3 failed: result isn't english.")
	}
	t.Log(string(plain))
	t.Log(string(Xor(plain[0:10], ciph[0:10])))
}

// Challenge 4
func TestChallenge4(t *testing.T) {
	text := readFile(t, "challenge-data/4.txt")
	maxScore := math.Inf(-1)
	var plain []byte
	for _, ciphLine := range strings.Split(string(text), "\n") {
		line := DecryptSingleXor(DecodeHex(ciphLine), ScoreEnglish)
		s := ScoreEnglish(line)
		if s > maxScore {
			maxScore = s
			plain = line
		}
	}
	if !isEnglish(plain) {
		t.Fatal("Challenge 4 failed: result isn't english.")
	}
	t.Log(string(plain))
}

func BenchmarkChallenge4(b *testing.B) {
	buf := make([]byte, 100)
	rand.Seed(666)
	for i := 0; i < b.N; i++ {
		rand.Read(buf)
		DecryptSingleXor(buf, ScoreEnglish)
	}
}

// Challenge 5
func TestRepeatingXor(t *testing.T) {
	text := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	ciph := EncodeHex(Xor(text, []byte("ICE")))
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if ciph != expected {
		t.Fatalf("Challenge 5 failed; expected:\n%s\ngot:\n%s\n", expected, ciph)
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
	dist2 := editDistPerBit(Xor(text[0:20], []byte("wonderfulwonderfulwo")), Xor(text[20:40], []byte("erfulwonderfulwonder")))
	if dist1 >= dist2 {
		t.Fatal("editDistPerBit: unexpected result")
	}
	t.Log(dist1, dist2)
}

func TestVigenere(t *testing.T) {
	ciph := readFile(t, "challenge-data/6.txt")
	ciph = DecodeBase64(string(ciph))

	plain, key := DecryptVigenere(ciph, ScoreEnglish)
	if !isEnglish(plain) || !isEnglish(key) {
		t.Fatal("Challenge 6 failed: result is not english.")
	}
	t.Log(string(key))
	writeFile(t, "challenge-data/6_plain.txt", plain)
}

// Challenge 7
func TestDecryptECB(t *testing.T) {
	text := readFile(t, "challenge-data/7.txt")
	text = DecodeBase64(string(text))
	c, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}
	plain := DecryptECB(text, c)
	if !isEnglish(plain) {
		t.Fatal("Challenge 7 failed: result is not english.")
	}
	writeFile(t, "challenge-data/7_plain.txt", plain)
}

// Challenge 8
func TestDetectECB(t *testing.T) {
	text := readFile(t, "challenge-data/8.txt")
	lineNum := -1
	for i, line := range strings.Split(string(text), "\n") {
		if DetectECB(DecodeHex(line), 16) {
			lineNum = i + 1
		}
	}
	if lineNum == -1 {
		t.Fatal("Challenge 8 failed: ECB not found.")
	}
	t.Log("ECB line number is", lineNum)
}
