package server

import (
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/protocol"
	"socketproxy/internal/relay"
)

// Server is a Shadowsocks AEAD server supporting TCP and UDP relay.
type Server struct {
	Addr      string
	UDPAddr   string
	Method    cipher.Method
	MasterKey []byte
	Timeout   time.Duration
	replay    *ReplayCache

	udpMu       sync.Mutex
	udpSessions map[string]*udpSession
}

func New(addr string, method cipher.Method, masterKey []byte, timeout time.Duration) *Server {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Server{
		Addr:        addr,
		Method:      method,
		MasterKey:   masterKey,
		Timeout:     timeout,
		replay:      NewReplayCache(10 * time.Minute),
		udpSessions: make(map[string]*udpSession),
	}
}

func (s *Server) ListenAndServe() error {
	if s.UDPAddr != "" {
		uaddr, err := net.ResolveUDPAddr("udp", s.UDPAddr)
		if err != nil {
			return err
		}
		udpLn, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			return err
		}
		go s.ServeUDP(udpLn)
	}

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
	conn.SetDeadline(time.Now().Add(s.Timeout))

	salt := make([]byte, s.Method.SaltSize())
	if _, err := io.ReadFull(conn, salt); err != nil {
		return
	}
	if !s.replay.Add(salt) {
		return
	}

	r, err := protocol.NewReaderWithSalt(conn, s.Method, s.MasterKey, salt)
	if err != nil {
		return
	}
	host, port, err := protocol.ReadAddress(r)
	if err != nil {
		return
	}

	w, err := protocol.NewWriter(conn, s.Method, s.MasterKey)
	if err != nil {
		return
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), s.Timeout)
	if err != nil {
		return
	}
	defer target.Close()

	conn.SetDeadline(time.Time{})
	relay.Relay(&conn2{Conn: conn, r: r, w: w}, target)
}

type conn2 struct {
	net.Conn
	r *protocol.Reader
	w *protocol.Writer
}

func (c *conn2) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *conn2) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *conn2) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
