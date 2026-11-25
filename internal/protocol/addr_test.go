package protocol

import (
	"bytes"
	"testing"
)

func TestAddressRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port int
	}{
		{"127.0.0.1", 1080},
		{"0.0.0.0", 0},
		{"255.255.255.255", 65535},
		{"::1", 443},
		{"2001:db8::1", 8388},
		{"example.com", 80},
		{"a", 1},
	}
	for _, c := range cases {
		enc, err := EncodeAddress(c.host, c.port)
		if err != nil {
			t.Fatalf("encode %s:%d: %v", c.host, c.port, err)
		}
		host, port, err := ReadAddress(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("decode %s:%d: %v", c.host, c.port, err)
		}
		if host != c.host || port != c.port {
			t.Fatalf("round trip = %s:%d, want %s:%d", host, port, c.host, c.port)
		}
	}
}

func TestEncodeInvalid(t *testing.T) {
	if _, err := EncodeAddress("example.com", -1); err == nil {
		t.Fatal("expected error for negative port")
	}
	if _, err := EncodeAddress("example.com", 70000); err == nil {
		t.Fatal("expected error for port out of range")
	}
	long := string(bytes.Repeat([]byte("a"), 256))
	if _, err := EncodeAddress(long, 80); err == nil {
		t.Fatal("expected error for over-long domain")
	}
}

func TestReadUnsupportedType(t *testing.T) {
	if _, _, err := ReadAddress(bytes.NewReader([]byte{0x02, 0, 0})); err == nil {
		t.Fatal("expected error for unsupported address type")
	}
}

func TestReadTruncated(t *testing.T) {
	enc, _ := EncodeAddress("127.0.0.1", 80)
	if _, _, err := ReadAddress(bytes.NewReader(enc[:3])); err == nil {
		t.Fatal("expected error for truncated address")
	}
}
