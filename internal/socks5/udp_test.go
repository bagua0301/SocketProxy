package socks5

import (
	"bytes"
	"testing"

	"socketproxy/internal/protocol"
)

func TestParseUDPDatagram(t *testing.T) {
	addr, err := protocol.EncodeAddress("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("dns-query")
	b := append([]byte{0, 0, 0}, addr...)
	b = append(b, payload...)

	host, port, got, err := parseUDPDatagram(b)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || port != 53 {
		t.Fatalf("addr = %s:%d", host, port)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q", got)
	}
}

func TestParseUDPDatagramFrag(t *testing.T) {
	if _, _, _, err := parseUDPDatagram([]byte{0, 0, 1, 1, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("expected error for fragmented datagram")
	}
}

func TestBuildUDPDatagramRoundTrip(t *testing.T) {
	pkt, err := buildUDPDatagram("127.0.0.1", 5353, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	host, port, payload, err := parseUDPDatagram(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != 5353 || string(payload) != "x" {
		t.Fatalf("round trip = %s:%d %q", host, port, payload)
	}
}
