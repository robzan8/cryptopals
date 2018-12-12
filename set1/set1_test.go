package cryptopals

import "testing"

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
