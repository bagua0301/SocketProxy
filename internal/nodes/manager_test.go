package nodes

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/config"
	"socketproxy/internal/crypto"
	"socketproxy/internal/server"
)

func startSSServer(t *testing.T, methodName, password string) (net.Listener, int) {
	t.Helper()
	method, err := cipher.FromName(methodName)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.EVPBytesToKey(password, method.KeySize())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(ln.Addr().String(), method, key, 5*time.Second)
	go srv.Serve(ln)
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func startEchoServer(t *testing.T) (net.Listener, int) {
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
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestManagerFailover(t *testing.T) {
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()
	ssLn, ssPort := startSSServer(t, cipher.MethodAES128GCM, "pw")
	defer ssLn.Close()

	m, err := NewManager(&config.ClientConfig{
		Strategy: "failover",
		Nodes: []config.Node{
			{Name: "dead", Server: "127.0.0.1", Port: 1, Password: "pw", Method: cipher.MethodAES128GCM, Timeout: 2},
			{Name: "live", Server: "127.0.0.1", Port: ssPort, Password: "pw", Method: cipher.MethodAES128GCM, Timeout: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := m.Dial(net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("failover-data")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
	if m.Current().Name != "live" {
		t.Fatalf("current = %q, want live", m.Current().Name)
	}
}

func TestManagerManualNoFailover(t *testing.T) {
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	m, err := NewManager(&config.ClientConfig{
		Strategy: "manual",
		Nodes: []config.Node{
			{Name: "dead", Server: "127.0.0.1", Port: 1, Password: "pw", Method: cipher.MethodAES128GCM, Timeout: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Dial(net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort))); err == nil {
		t.Fatal("expected dial failure for manual strategy")
	}
}

func TestManagerManualFallback(t *testing.T) {
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()
	ssLn, ssPort := startSSServer(t, cipher.MethodAES256GCM, "pw")
	defer ssLn.Close()

	m, err := NewManager(&config.ClientConfig{
		Strategy: "manual",
		Node:     "dead",
		Nodes: []config.Node{
			{Name: "dead", Server: "127.0.0.1", Port: 1, Password: "pw", Method: cipher.MethodAES256GCM, Timeout: 1},
			{Name: "live", Server: "127.0.0.1", Port: ssPort, Password: "pw", Method: cipher.MethodAES256GCM, Timeout: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := m.Dial(net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("manual-fallback")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
	if m.Current().Name != "dead" {
		t.Fatalf("manual current = %q, want dead (preference unchanged)", m.Current().Name)
	}
}

func TestCheckAll(t *testing.T) {
	ssLn, ssPort := startSSServer(t, cipher.MethodAES256GCM, "pw")
	defer ssLn.Close()

	m, err := NewManager(&config.ClientConfig{
		Strategy: "latency",
		Nodes: []config.Node{
			{Name: "live", Server: "127.0.0.1", Port: ssPort, Password: "pw", Method: cipher.MethodAES256GCM, Timeout: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.CheckAll(ctx)

	infos := m.Infos()
	if len(infos) != 1 {
		t.Fatalf("got %d infos", len(infos))
	}
	if !infos[0].Checked || !infos[0].Healthy {
		t.Fatalf("node not healthy: %+v", infos[0])
	}
}

func TestUpdateNodesKeepsCurrent(t *testing.T) {
	m, err := NewManager(&config.ClientConfig{
		Strategy: "manual",
		Nodes: []config.Node{
			{Name: "a", Server: "1.1.1.1", Port: 8388, Password: "pw", Method: cipher.MethodAES128GCM, Timeout: 2},
			{Name: "b", Server: "2.2.2.2", Port: 8388, Password: "pw", Method: cipher.MethodAES128GCM, Timeout: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetCurrent("b"); err != nil {
		t.Fatal(err)
	}

	err = m.UpdateNodes([]config.Node{
		{Name: "c", Server: "3.3.3.3", Port: 8388, Password: "pw", Method: cipher.MethodAES128GCM, Timeout: 2},
		{Name: "b", Server: "2.2.2.2", Port: 8388, Password: "pw", Method: cipher.MethodAES128GCM, Timeout: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Current().Name != "b" {
		t.Fatalf("current = %q, want b", m.Current().Name)
	}
}

func TestUnknownStrategy(t *testing.T) {
	_, err := NewManager(&config.ClientConfig{
		Strategy: "bogus",
		Nodes: []config.Node{
			{Name: "a", Server: "1.1.1.1", Port: 8388, Password: "pw", Method: cipher.MethodAES128GCM},
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown strategy")
	}
}
