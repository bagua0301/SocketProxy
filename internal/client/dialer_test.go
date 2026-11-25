package client

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/crypto"
	"socketproxy/internal/protocol"
)

// TestDialDoesNotWaitForServerSalt verifies that Dial returns without waiting
// for the server's response salt, which standard Shadowsocks servers only send
// once they have reply data.
func TestDialDoesNotWaitForServerSalt(t *testing.T) {
	method, err := cipher.FromName(cipher.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.EVPBytesToKey("pw", method.KeySize())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		salt := make([]byte, method.SaltSize())
		if _, err := io.ReadFull(conn, salt); err != nil {
			return
		}
		r, err := protocol.NewReaderWithSalt(conn, method, key, salt)
		if err != nil {
			return
		}
		if _, _, err := protocol.ReadAddress(r); err != nil {
			return
		}

		buf := make([]byte, 1024)
		n, err := r.Read(buf)
		if err != nil {
			return
		}

		// Only reply (and send the response salt) after receiving payload.
		w, err := protocol.NewWriter(conn, method, key)
		if err != nil {
			return
		}
		w.Write(buf[:n])
	}()

	d := &Dialer{
		ServerAddr: ln.Addr().String(),
		Method:     method,
		MasterKey:  key,
		Timeout:    2 * time.Second,
	}

	start := time.Now()
	conn, err := d.Dial("example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Dial blocked for %v waiting for server salt", elapsed)
	}

	payload := []byte("GET / HTTP/1.0\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}
