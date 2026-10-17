package paypercrawl

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

// Vectors from tests/unit.php of the WordPress plugin (empty, abc) plus padding-edge cases
// (135/136/137 bytes around the 136-byte rate) generated with viem keccak256.
func TestKeccakVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
		{strings.Repeat("a", 135), "0x34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"},
		{strings.Repeat("a", 136), "0xa6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"},
		{strings.Repeat("a", 137), "0xd869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"},
		{strings.Repeat("xyz", 100), "0xcc0b928a8fb33dca301e35d6070e6cccfda8a90b0ce76912018dd71168c42ad2"},
	}
	for _, c := range cases {
		if got := Keccak256Hex([]byte(c.in)); got != c.want {
			t.Errorf("len %d: got %s want %s", len(c.in), got, c.want)
		}
	}
}

func TestKeccakMatchesXCrypto(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 600; n += 7 {
		data := make([]byte, n)
		rng.Read(data)
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		want := h.Sum(nil)
		got := Keccak256(data)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("len %d mismatch", n)
		}
	}
}
