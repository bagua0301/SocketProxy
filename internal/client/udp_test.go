package client

import (
	"bytes"
	"net"
	"testing"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/config"
	"socketproxy/internal/crypto"
	"socketproxy/internal/server"
)

func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn
}

func TestUDPConnRoundTrip(t *testing.T) {
	echo := startUDPEcho(t)
	defer echo.Close()
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	method, err := cipher.FromName(cipher.MethodChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.EVPBytesToKey("udp-secret", method.KeySize())

	ssLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New("127.0.0.1:0", method, key, 5*time.Second)
	go srv.ServeUDP(ssLn)
	defer ssLn.Close()

	dialer, err := New(config.Node{
		Name:     "udp",
		Server:   "127.0.0.1",
		Port:     ssLn.LocalAddr().(*net.UDPAddr).Port,
		Password: "udp-secret",
		Method:   cipher.MethodChaCha20Poly1305,
		UDP:      true,
		Timeout:  5,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialer.DialUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("hello-udp-payload")
	if _, err := conn.WriteTo(payload, "127.0.0.1", echoAddr.Port); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	n, host, port, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch: got %q", buf[:n])
	}
	if host != "127.0.0.1" || port != echoAddr.Port {
		t.Fatalf("source = %s:%d, want 127.0.0.1:%d", host, port, echoAddr.Port)
	}
}
