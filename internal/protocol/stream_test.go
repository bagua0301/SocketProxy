package protocol

import (
	"bytes"
	"io"
	"testing"

	spcipher "socketproxy/internal/cipher"
	spcrypto "socketproxy/internal/crypto"
)

func testKey(m spcipher.Method) []byte {
	return spcrypto.EVPBytesToKey("test-password", m.KeySize())
}

func TestStreamRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("hello world "), 10000) // 120000 bytes, multiple chunks
	for _, name := range spcipher.Names() {
		t.Run(name, func(t *testing.T) {
			m, err := spcipher.FromName(name)
			if err != nil {
				t.Fatal(err)
			}
			key := testKey(m)

			var buf bytes.Buffer
			w, err := NewWriter(&buf, m, key)
			if err != nil {
				t.Fatal(err)
			}
			n, err := w.Write(payload)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(payload) {
				t.Fatalf("wrote %d, want %d", n, len(payload))
			}

			r, err := NewReader(&buf, m, key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %d bytes", len(got))
			}
		})
	}
}

func TestStreamSmallWrites(t *testing.T) {
	m, _ := spcipher.FromName(spcipher.MethodAES128GCM)
	key := testKey(m)

	var buf bytes.Buffer
	w, err := NewWriter(&buf, m, key)
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{"a", "bc", "", "def", "ghij"}
	for _, p := range parts {
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := NewReader(&buf, m, key)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdefghij" {
		t.Fatalf("got %q", got)
	}
}

func TestStreamTamperedPayload(t *testing.T) {
	m, _ := spcipher.FromName(spcipher.MethodAES256GCM)
	key := testKey(m)

	var buf bytes.Buffer
	w, _ := NewWriter(&buf, m, key)
	if _, err := w.Write([]byte("sensitive data")); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	raw[len(raw)-1] ^= 0xFF // corrupt final byte of ciphertext

	r, err := NewReader(bytes.NewReader(raw), m, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected authentication failure for tampered payload")
	}
}

func TestStreamWrongKey(t *testing.T) {
	m, _ := spcipher.FromName(spcipher.MethodChaCha20Poly1305)
	key := testKey(m)

	var buf bytes.Buffer
	w, _ := NewWriter(&buf, m, key)
	w.Write([]byte("data"))

	wrongKey := spcrypto.EVPBytesToKey("other-password", m.KeySize())
	r, err := NewReader(bytes.NewReader(buf.Bytes()), m, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected failure with wrong key")
	}
}

func TestNonceIncrement(t *testing.T) {
	var n [12]byte
	incNonce(&n)
	if n[0] != 1 {
		t.Fatalf("n[0] = %d, want 1", n[0])
	}
	n = [12]byte{0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	incNonce(&n)
	if n[0] != 0 || n[1] != 0 || n[2] != 1 {
		t.Fatalf("carry not propagated: %v", n)
	}
}
