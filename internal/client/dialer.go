package client

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/config"
	"socketproxy/internal/crypto"
	"socketproxy/internal/protocol"
)

// Dialer establishes Shadowsocks AEAD TCP connections through a single node.
type Dialer struct {
	ServerAddr string
	Method     cipher.Method
	MasterKey  []byte
	Timeout    time.Duration
}

// New creates a Dialer for the given node.
func New(node config.Node) (*Dialer, error) {
	method, err := cipher.FromName(node.Method)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		ServerAddr: net.JoinHostPort(node.Server, strconv.Itoa(node.Port)),
		Method:     method,
		MasterKey:  crypto.EVPBytesToKey(node.Password, method.KeySize()),
		Timeout:    node.DialTimeout(),
	}, nil
}

func (d *Dialer) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return 10 * time.Second
}

// Dial connects to the Shadowsocks server and returns a net.Conn whose reads
// and writes are transparently encrypted. target is "host:port"; domains are
// forwarded to the server unmodified.
func (d *Dialer) Dial(target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}
	addr, err := protocol.EncodeAddress(host, port)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", d.ServerAddr, d.timeout())
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	conn.SetDeadline(time.Now().Add(d.timeout()))
	w, err := protocol.NewWriter(conn, d.Method, d.MasterKey)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(addr); err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})

	ok = true
	return &Conn{Conn: conn, method: d.Method, masterKey: d.MasterKey, w: w}, nil
}

// Conn is an encrypted Shadowsocks connection.
//
// The response salt is read lazily on the first Read because standard
// Shadowsocks servers do not send their salt until they have reply data.
type Conn struct {
	net.Conn
	method    cipher.Method
	masterKey []byte
	w         *protocol.Writer

	once sync.Once
	r    *protocol.Reader
	rerr error
}

func (c *Conn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		c.r, c.rerr = protocol.NewReader(c.Conn, c.method, c.masterKey)
	})
	if c.rerr != nil {
		return 0, c.rerr
	}
	return c.r.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
