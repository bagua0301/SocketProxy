package client

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/crypto"
	"socketproxy/internal/protocol"
	"socketproxy/internal/relay"
)

// UDPConn is a Shadowsocks AEAD UDP client. Each datagram is independently
// encrypted with a fresh salt and an all-zero nonce.
type UDPConn struct {
	conn      *net.UDPConn
	method    cipher.Method
	masterKey []byte
	readBuf   []byte
}

func NewUDPConn(serverAddr string, method cipher.Method, masterKey []byte) (*UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve server %q: %w", serverAddr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	return &UDPConn{
		conn:      conn,
		method:    method,
		masterKey: masterKey,
		readBuf:   make([]byte, 64*1024),
	}, nil
}

// DialUDP creates a Shadowsocks UDP client for this node.
func (d *Dialer) DialUDP() (relay.PacketConn, error) {
	return NewUDPConn(d.ServerAddr, d.Method, d.MasterKey)
}

func (u *UDPConn) WriteTo(b []byte, host string, port int) (int, error) {
	addr, err := protocol.EncodeAddress(host, port)
	if err != nil {
		return 0, err
	}

	salt := make([]byte, u.method.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	aead, err := u.method.NewAEAD(crypto.Subkey(u.masterKey, salt, u.method.KeySize()))
	if err != nil {
		return 0, err
	}

	plaintext := make([]byte, 0, len(addr)+len(b))
	plaintext = append(plaintext, addr...)
	plaintext = append(plaintext, b...)

	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, plaintext, nil)

	packet := make([]byte, 0, len(salt)+len(sealed))
	packet = append(packet, salt...)
	packet = append(packet, sealed...)

	if _, err := u.conn.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (u *UDPConn) ReadFrom(b []byte) (int, string, int, error) {
	n, err := u.conn.Read(u.readBuf)
	if err != nil {
		return 0, "", 0, err
	}

	saltLen := u.method.SaltSize()
	if n < saltLen {
		return 0, "", 0, errors.New("short udp packet")
	}
	salt := u.readBuf[:saltLen]
	sealed := u.readBuf[saltLen:n]

	aead, err := u.method.NewAEAD(crypto.Subkey(u.masterKey, salt, u.method.KeySize()))
	if err != nil {
		return 0, "", 0, err
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return 0, "", 0, fmt.Errorf("decrypt udp packet: %w", err)
	}

	br := bytes.NewReader(plaintext)
	host, port, err := protocol.ReadAddress(br)
	if err != nil {
		return 0, "", 0, err
	}
	payload := plaintext[len(plaintext)-br.Len():]
	return copy(b, payload), host, port, nil
}

func (u *UDPConn) LocalAddr() net.Addr                { return u.conn.LocalAddr() }
func (u *UDPConn) SetReadDeadline(t time.Time) error  { return u.conn.SetReadDeadline(t) }
func (u *UDPConn) SetWriteDeadline(t time.Time) error { return u.conn.SetWriteDeadline(t) }
func (u *UDPConn) Close() error                       { return u.conn.Close() }
