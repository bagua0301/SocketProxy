package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEVPBytesToKeyKnownVector(t *testing.T) {
	want, err := hex.DecodeString("3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf")
	if err != nil {
		t.Fatal(err)
	}
	got := EVPBytesToKey("foobar", 32)
	if !bytes.Equal(got, want) {
		t.Fatalf("EVPBytesToKey mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestEVPBytesToKeyLength(t *testing.T) {
	for _, n := range []int{16, 32} {
		if got := len(EVPBytesToKey("secret", n)); got != n {
			t.Fatalf("len = %d, want %d", got, n)
		}
	}
	if got := EVPBytesToKey("secret", 0); got != nil {
		t.Fatalf("expected nil for zero key length, got %x", got)
	}
}

func TestSubkeyDeterministicAndSized(t *testing.T) {
	master := EVPBytesToKey("secret", 32)
	salt := bytes.Repeat([]byte{0x01}, 32)

	a := Subkey(master, salt, 32)
	b := Subkey(master, salt, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("subkey derivation is not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("len = %d, want 32", len(a))
	}

	other := Subkey(master, bytes.Repeat([]byte{0x02}, 32), 32)
	if bytes.Equal(a, other) {
		t.Fatal("different salts produced the same subkey")
	}
}
