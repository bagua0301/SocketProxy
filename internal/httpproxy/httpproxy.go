// Package httpproxy is a minimal HTTP proxy supporting CONNECT (HTTPS) and
// absolute-form plain HTTP requests, used to drive browsers through the
// Shadowsocks tunnel via the system proxy setting.
package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"socketproxy/internal/relay"
)

// DialFunc opens a proxied connection to target ("host:port").
type DialFunc func(target string) (net.Conn, error)

type Server struct {
	Addr    string
	Dial    DialFunc
	Timeout time.Duration
}

func New(addr string, dial DialFunc) *Server {
	return &Server{Addr: addr, Dial: dial, Timeout: 30 * time.Second}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	if s.Timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
	}
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		s.handleConnect(conn, br, req)
		return
	}
	s.handleHTTP(conn, req)
}

func (s *Server) handleConnect(conn net.Conn, br *bufio.Reader, req *http.Request) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if target == "" {
		writeStatus(conn, http.StatusBadRequest)
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	upstream, err := s.Dial(target)
	if err != nil {
		writeStatus(conn, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	relay.Relay(&bufferedConn{Conn: conn, r: br}, upstream)
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (s *Server) handleHTTP(conn net.Conn, req *http.Request) {
	if !req.URL.IsAbs() || req.URL.Host == "" {
		writeStatus(conn, http.StatusBadRequest)
		return
	}

	target := req.URL.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	upstream, err := s.Dial(target)
	if err != nil {
		writeStatus(conn, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Set("Connection", "close")
	req.Close = true

	if err := req.Write(upstream); err != nil {
		return
	}
	io.Copy(conn, upstream)
}

func writeStatus(conn net.Conn, code int) {
	body := http.StatusText(code)
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, body, len(body), body)
}
