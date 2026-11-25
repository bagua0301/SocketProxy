package server

import (
	"bytes"
	"crypto/rand"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"socketproxy/internal/crypto"
	"socketproxy/internal/protocol"
)

const udpIdleTimeout = 2 * time.Minute

type udpSession struct {
	key        string
	conn       *net.UDPConn
	clientAddr *net.UDPAddr
	targetAddr *net.UDPAddr
	lastSeen   atomic.Int64
}

// ServeUDP relays Shadowsocks AEAD UDP packets received on ln. It blocks until
// ln is closed.
func (s *Server) ServeUDP(ln *net.UDPConn) error {
	defer s.closeUDPSessions()

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		s.handleUDPPacket(ln, clientAddr, packet)
	}
}

func (s *Server) handleUDPPacket(ln *net.UDPConn, clientAddr *net.UDPAddr, packet []byte) {
	saltLen := s.Method.SaltSize()
	if len(packet) < saltLen {
		return
	}
	salt := packet[:saltLen]
	sealed := packet[saltLen:]

	aead, err := s.Method.NewAEAD(crypto.Subkey(s.MasterKey, salt, s.Method.KeySize()))
	if err != nil {
		return
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return
	}

	br := bytes.NewReader(plaintext)
	host, port, err := protocol.ReadAddress(br)
	if err != nil {
		return
	}
	payload := plaintext[len(plaintext)-br.Len():]

	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}

	sess := s.getOrCreateUDPSession(ln, clientAddr, targetAddr)
	if sess == nil {
		return
	}
	sess.lastSeen.Store(time.Now().UnixNano())
	sess.conn.Write(payload)
}

func (s *Server) getOrCreateUDPSession(ln *net.UDPConn, clientAddr, targetAddr *net.UDPAddr) *udpSession {
	key := clientAddr.String() + "|" + targetAddr.String()

	s.udpMu.Lock()
	if sess, ok := s.udpSessions[key]; ok {
		s.udpMu.Unlock()
		return sess
	}

	conn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		s.udpMu.Unlock()
		return nil
	}
	sess := &udpSession{
		key:        key,
		conn:       conn,
		clientAddr: clientAddr,
		targetAddr: targetAddr,
	}
	sess.lastSeen.Store(time.Now().UnixNano())
	s.udpSessions[key] = sess
	s.udpMu.Unlock()

	go s.readUDPSession(ln, sess)
	return sess
}

func (s *Server) readUDPSession(ln *net.UDPConn, sess *udpSession) {
	buf := make([]byte, 64*1024)
	for {
		sess.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := sess.conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(time.Unix(0, sess.lastSeen.Load())) >= udpIdleTimeout {
					s.removeUDPSession(sess)
					return
				}
				continue
			}
			s.removeUDPSession(sess)
			return
		}

		sess.lastSeen.Store(time.Now().UnixNano())
		resp, err := s.encryptUDPResponse(sess.targetAddr, buf[:n])
		if err != nil {
			continue
		}
		ln.WriteToUDP(resp, sess.clientAddr)
	}
}

func (s *Server) encryptUDPResponse(addr *net.UDPAddr, payload []byte) ([]byte, error) {
	addrBytes, err := protocol.EncodeAddress(addr.IP.String(), addr.Port)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, s.Method.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := s.Method.NewAEAD(crypto.Subkey(s.MasterKey, salt, s.Method.KeySize()))
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 0, len(addrBytes)+len(payload))
	plaintext = append(plaintext, addrBytes...)
	plaintext = append(plaintext, payload...)

	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, plaintext, nil)

	packet := make([]byte, 0, len(salt)+len(sealed))
	packet = append(packet, salt...)
	packet = append(packet, sealed...)
	return packet, nil
}

func (s *Server) removeUDPSession(sess *udpSession) {
	s.udpMu.Lock()
	if cur, ok := s.udpSessions[sess.key]; ok && cur == sess {
		delete(s.udpSessions, sess.key)
	}
	s.udpMu.Unlock()
	sess.conn.Close()
}

func (s *Server) closeUDPSessions() {
	s.udpMu.Lock()
	sessions := s.udpSessions
	s.udpSessions = make(map[string]*udpSession)
	s.udpMu.Unlock()
	for _, sess := range sessions {
		sess.conn.Close()
	}
}
