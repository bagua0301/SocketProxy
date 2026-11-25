package socks5

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"socketproxy/internal/protocol"
	"socketproxy/internal/relay"
)

const (
	Version = 0x05

	authNone       = 0x00
	authUserPass   = 0x02
	authNoAccepted = 0xFF
	authVersion    = 0x01
	authSuccess    = 0x00
	authFailure    = 0x01

	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	RepSuccess          = 0x00
	RepGeneralFailure   = 0x01
	RepNotAllowed       = 0x02
	RepCmdNotSupported  = 0x07
	RepAddrNotSupported = 0x08
)

// DialFunc opens a proxied connection to target ("host:port").
type DialFunc func(target string) (net.Conn, error)

// Credentials is a SOCKS5 username/password pair (RFC 1929).
type Credentials struct {
	Username string
	Password string
}

// Server is a local SOCKS5 server that forwards CONNECT requests through Dial.
type Server struct {
	Addr    string
	Dial    DialFunc
	DialUDP func() (relay.PacketConn, error)
	Auth    *Credentials
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
	conn.SetDeadline(time.Now().Add(s.Timeout))

	if err := s.handshake(conn); err != nil {
		return
	}
	cmd, host, port, err := readRequest(conn)
	if err != nil {
		return
	}

	switch cmd {
	case CmdConnect:
		target := net.JoinHostPort(host, strconv.Itoa(port))
		upstream, err := s.Dial(target)
		if err != nil {
			writeReply(conn, RepGeneralFailure)
			return
		}
		defer upstream.Close()
		if err := writeReply(conn, RepSuccess); err != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		relay.Relay(conn, upstream)
	case CmdUDPAssociate:
		if s.DialUDP == nil {
			writeReply(conn, RepCmdNotSupported)
			return
		}
		s.handleUDPAssociate(conn)
	default:
		writeReply(conn, RepCmdNotSupported)
	}
}

func (s *Server) handshake(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != Version {
		return fmt.Errorf("unsupported socks version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	if s.Auth != nil && s.Auth.Username != "" {
		if !hasMethod(methods, authUserPass) {
			conn.Write([]byte{Version, authNoAccepted})
			return errors.New("client does not support username/password auth")
		}
		if _, err := conn.Write([]byte{Version, authUserPass}); err != nil {
			return err
		}
		return s.authenticate(conn)
	}

	if hasMethod(methods, authNone) {
		_, err := conn.Write([]byte{Version, authNone})
		return err
	}
	conn.Write([]byte{Version, authNoAccepted})
	return errors.New("no acceptable authentication method")
}

func hasMethod(methods []byte, want byte) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}

func (s *Server) authenticate(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != authVersion {
		return fmt.Errorf("unsupported auth version %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		return err
	}
	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	userOK := subtle.ConstantTimeCompare(username, []byte(s.Auth.Username)) == 1
	passOK := subtle.ConstantTimeCompare(password, []byte(s.Auth.Password)) == 1
	if userOK && passOK {
		_, err := conn.Write([]byte{authVersion, authSuccess})
		return err
	}

	conn.Write([]byte{authVersion, authFailure})
	return errors.New("invalid username or password")
}

func readRequest(conn net.Conn) (cmd byte, host string, port int, err error) {
	var header [3]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return 0, "", 0, err
	}
	if header[0] != Version {
		return 0, "", 0, fmt.Errorf("unsupported socks version %d", header[0])
	}
	cmd = header[1]
	host, port, err = protocol.ReadAddress(conn)
	return cmd, host, port, err
}

func writeReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{Version, rep, 0x00, protocol.AddrTypeIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
