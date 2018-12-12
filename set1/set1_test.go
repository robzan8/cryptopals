package cryptopals

import "testing"

// Challenge 1
func TestHexToBase64(t *testing.T) {
	res, err := hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if res != expected {
		t.Fatalf("hexToBase64 failed challange 1. Expected %s, got %s.\n", expected, res)
	}
}
