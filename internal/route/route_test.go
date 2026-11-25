package route

import (
	"errors"
	"net"
	"testing"
	"time"
)

func startListener(t *testing.T) (net.Listener, string) {
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
			c.Close()
		}
	}()
	return ln, ln.Addr().String()
}

func TestValidMode(t *testing.T) {
	for _, m := range []string{ModeAuto, ModeProxy, ModeDirect} {
		if !ValidMode(m) {
			t.Fatalf("%q should be valid", m)
		}
	}
	if ValidMode("bogus") {
		t.Fatal("bogus should be invalid")
	}
}

func TestDirectMode(t *testing.T) {
	ln, addr := startListener(t)
	defer ln.Close()

	proxyCalled := false
	d := &Dialer{
		Mode:          ModeDirect,
		DirectTimeout: time.Second,
		Proxy: func(string) (net.Conn, error) {
			proxyCalled = true
			return nil, nil
		},
	}
	conn, err := d.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if proxyCalled {
		t.Fatal("proxy must not be used in direct mode")
	}
}

func TestAutoDirectSuccess(t *testing.T) {
	ln, addr := startListener(t)
	defer ln.Close()

	proxyCalled := false
	d := &Dialer{
		Mode:          ModeAuto,
		DirectTimeout: time.Second,
		Proxy: func(string) (net.Conn, error) {
			proxyCalled = true
			return nil, nil
		},
	}
	conn, err := d.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if proxyCalled {
		t.Fatal("proxy must not be used when direct succeeds")
	}
}

func TestAutoFallbackToProxy(t *testing.T) {
	proxyCalled := false
	client, server := net.Pipe()
	defer server.Close()

	d := &Dialer{
		Mode:          ModeAuto,
		DirectTimeout: 300 * time.Millisecond,
		Proxy: func(string) (net.Conn, error) {
			proxyCalled = true
			return client, nil
		},
	}
	conn, err := d.Dial("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !proxyCalled {
		t.Fatal("expected fallback to proxy")
	}
}

func TestProxyModeAlwaysProxies(t *testing.T) {
	proxyCalled := false
	client, server := net.Pipe()
	defer server.Close()

	d := &Dialer{
		Mode: ModeProxy,
		Proxy: func(string) (net.Conn, error) {
			proxyCalled = true
			return client, nil
		},
	}
	conn, err := d.Dial("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !proxyCalled {
		t.Fatal("expected proxy in proxy mode")
	}
}

func TestAutoCachesDirectFailure(t *testing.T) {
	directCalls := 0
	proxyCalls := 0

	d := &Dialer{
		Mode:          ModeAuto,
		DirectTimeout: time.Second,
		dialDirect: func(string, time.Duration) (net.Conn, error) {
			directCalls++
			return nil, errors.New("blocked")
		},
		Proxy: func(string) (net.Conn, error) {
			proxyCalls++
			client, server := net.Pipe()
			server.Close()
			return client, nil
		},
	}

	for i := 0; i < 3; i++ {
		conn, err := d.Dial("www.google.com:443")
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	if directCalls != 1 {
		t.Fatalf("directCalls = %d, want 1 (subsequent dials use cache)", directCalls)
	}
	if proxyCalls != 3 {
		t.Fatalf("proxyCalls = %d, want 3", proxyCalls)
	}
}
