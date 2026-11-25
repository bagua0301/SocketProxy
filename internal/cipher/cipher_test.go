package cipher

import (
	"bytes"
	"testing"
)

func TestMethodsRoundTrip(t *testing.T) {
	plain := []byte("the quick brown fox jumps over the lazy dog")
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			m, err := FromName(name)
			if err != nil {
				t.Fatal(err)
			}
			key := bytes.Repeat([]byte{0x42}, m.KeySize())
			aead, err := m.NewAEAD(key)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, aead.NonceSize())
			sealed := aead.Seal(nil, nonce, plain, nil)
			got, err := aead.Open(nil, nonce, sealed, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round trip mismatch: got %q", got)
			}
		})
	}
}

func TestWrongKeyFails(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			m, _ := FromName(name)
			key := bytes.Repeat([]byte{0x01}, m.KeySize())
			aead, _ := m.NewAEAD(key)
			nonce := make([]byte, aead.NonceSize())
			sealed := aead.Seal(nil, nonce, []byte("data"), nil)

			wrong := bytes.Repeat([]byte{0x02}, m.KeySize())
			badAEAD, _ := m.NewAEAD(wrong)
			if _, err := badAEAD.Open(nil, nonce, sealed, nil); err == nil {
				t.Fatal("expected authentication failure with wrong key")
			}
		})
	}
}

func TestInvalidKeyLength(t *testing.T) {
	for _, name := range Names() {
		m, _ := FromName(name)
		if _, err := m.NewAEAD([]byte{1, 2, 3}); err == nil {
			t.Fatalf("%s: expected error for short key", name)
		}
	}
}

func TestFromNameUnknown(t *testing.T) {
	if _, err := FromName("nope"); err == nil {
		t.Fatal("expected error for unknown method")
	}
}
