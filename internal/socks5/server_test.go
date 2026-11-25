package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"socketproxy/internal/protocol"
)

func startEchoDial() DialFunc {
	return func(target string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			io.Copy(server, server)
		}()
		return client, nil
	}
}

func TestConnectEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := New(ln.Addr().String(), startEchoDial())
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{Version, 1, authNone}); err != nil {
		t.Fatal(err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodReply); err != nil {
		t.Fatal(err)
	}
	if methodReply[0] != Version || methodReply[1] != authNone {
		t.Fatalf("unexpected method reply %v", methodReply)
	}

	addr, _ := protocol.EncodeAddress("127.0.0.1", 80)
	req := append([]byte{Version, CmdConnect, 0x00}, addr...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != Version || reply[1] != RepSuccess {
		t.Fatalf("unexpected connect reply %v", reply)
	}

	payload := []byte("ping-pong")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q", got)
	}
}

func TestUDPAssociateNotSupported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := New(ln.Addr().String(), startEchoDial())
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte{Version, 1, authNone})
	io.ReadFull(conn, make([]byte, 2))

	addr, _ := protocol.EncodeAddress("127.0.0.1", 53)
	req := append([]byte{Version, CmdUDPAssociate, 0x00}, addr...)
	conn.Write(req)

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != RepCmdNotSupported {
		t.Fatalf("rep = 0x%02x, want 0x%02x", reply[1], RepCmdNotSupported)
	}
}

func TestNoAcceptableAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := New(ln.Addr().String(), startEchoDial())
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte{Version, 1, 0x02})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != authNoAccepted {
		t.Fatalf("reply = %v, want no-acceptable", reply)
	}
}

func startAuthServer(t *testing.T, username, password string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := New(ln.Addr().String(), startEchoDial())
	srv.Auth = &Credentials{Username: username, Password: password}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { ln.Close() }
}

func doAuth(t *testing.T, conn net.Conn, username, password string) byte {
	t.Helper()
	if _, err := conn.Write([]byte{Version, 2, authNone, authUserPass}); err != nil {
		t.Fatal(err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodReply); err != nil {
		t.Fatal(err)
	}
	if methodReply[1] != authUserPass {
		return methodReply[1]
	}

	msg := []byte{authVersion, byte(len(username))}
	msg = append(msg, username...)
	msg = append(msg, byte(len(password)))
	msg = append(msg, password...)
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		t.Fatal(err)
	}
	return status[1]
}

func TestAuthSuccess(t *testing.T) {
	addr, stop := startAuthServer(t, "alice", "s3cret")
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if status := doAuth(t, conn, "alice", "s3cret"); status != authSuccess {
		t.Fatalf("auth status = 0x%02x, want success", status)
	}

	addrBytes, _ := protocol.EncodeAddress("127.0.0.1", 80)
	req := append([]byte{Version, CmdConnect, 0x00}, addrBytes...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != RepSuccess {
		t.Fatalf("connect reply = 0x%02x", reply[1])
	}

	payload := []byte("authenticated")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q", got)
	}
}

func TestAuthFailure(t *testing.T) {
	addr, stop := startAuthServer(t, "alice", "s3cret")
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if status := doAuth(t, conn, "alice", "wrong"); status != authFailure {
		t.Fatalf("auth status = 0x%02x, want failure", status)
	}

	conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("expected connection to be closed after auth failure")
	}
}

func TestAuthRequiredNotOffered(t *testing.T) {
	addr, stop := startAuthServer(t, "alice", "s3cret")
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{Version, 1, authNone}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != authNoAccepted {
		t.Fatalf("reply = %v, want no-acceptable", reply)
	}
}
