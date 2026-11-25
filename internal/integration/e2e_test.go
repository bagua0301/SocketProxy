package integration

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/client"
	"socketproxy/internal/config"
	"socketproxy/internal/crypto"
	"socketproxy/internal/protocol"
	"socketproxy/internal/server"
	"socketproxy/internal/socks5"
)

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln
}

func socksConnect(t *testing.T, conn net.Conn, host string, port int) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{socks5.Version, 1, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != socks5.Version || reply[1] != 0x00 {
		t.Fatalf("handshake reply %v", reply)
	}

	addr, err := protocol.EncodeAddress(host, port)
	if err != nil {
		t.Fatal(err)
	}
	req := append([]byte{socks5.Version, socks5.CmdConnect, 0x00}, addr...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply = make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != socks5.RepSuccess {
		t.Fatalf("connect failed, rep=0x%02x", reply[1])
	}
}

func TestEndToEnd(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	method, err := cipher.FromName(cipher.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.EVPBytesToKey("e2e-password", method.KeySize())

	ssLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ssSrv := server.New(ssLn.Addr().String(), method, key, 10*time.Second)
	go ssSrv.Serve(ssLn)
	defer ssLn.Close()

	node := config.Node{
		Name:     "local",
		Server:   "127.0.0.1",
		Port:     ssLn.Addr().(*net.TCPAddr).Port,
		Password: "e2e-password",
		Method:   cipher.MethodAES256GCM,
		Timeout:  10,
	}
	dialer, err := client.New(node)
	if err != nil {
		t.Fatal(err)
	}

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksSrv := socks5.New(socksLn.Addr().String(), dialer.Dial)
	go socksSrv.Serve(socksLn)
	defer socksLn.Close()

	targetPort := echo.Addr().(*net.TCPAddr).Port

	conn, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Use a domain name to exercise domain address encoding end to end.
	socksConnect(t, conn, "localhost", targetPort)

	payload := bytes.Repeat([]byte("payload-block-"), 20000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
