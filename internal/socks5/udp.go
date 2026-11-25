package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"socketproxy/internal/protocol"
)

const udpIdleTimeout = 2 * time.Minute

func (s *Server) handleUDPAssociate(ctrl net.Conn) {
	tcpLocal, ok := ctrl.LocalAddr().(*net.TCPAddr)
	if !ok {
		writeReply(ctrl, RepGeneralFailure)
		return
	}

	bindIP := tcpLocal.IP
	if bindIP == nil || bindIP.IsUnspecified() {
		bindIP = net.IPv4zero
	}
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		writeReply(ctrl, RepGeneralFailure)
		return
	}
	defer udpLn.Close()

	upstream, err := s.DialUDP()
	if err != nil {
		writeReply(ctrl, RepGeneralFailure)
		return
	}
	defer upstream.Close()

	bnd := udpLn.LocalAddr().(*net.UDPAddr)
	replyIP := tcpLocal.IP
	if replyIP == nil || replyIP.IsUnspecified() {
		replyIP = net.IPv4(127, 0, 0, 1)
	}
	if err := writeUDPReply(ctrl, replyIP, bnd.Port); err != nil {
		return
	}

	ctrl.SetDeadline(time.Time{})

	var (
		once      sync.Once
		done      = make(chan struct{})
		clientMu  sync.Mutex
		clientUDP *net.UDPAddr
	)
	closeAll := func() {
		once.Do(func() {
			udpLn.Close()
			upstream.Close()
			close(done)
		})
	}
	getClient := func() *net.UDPAddr {
		clientMu.Lock()
		defer clientMu.Unlock()
		return clientUDP
	}
	setClient := func(addr *net.UDPAddr) {
		clientMu.Lock()
		clientUDP = addr
		clientMu.Unlock()
	}

	go func() {
		io.Copy(io.Discard, ctrl)
		closeAll()
	}()

	go func() {
		buf := make([]byte, 64*1024)
		for {
			upstream.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, host, port, err := upstream.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				closeAll()
				return
			}
			dst := getClient()
			if dst == nil {
				continue
			}
			packet, err := buildUDPDatagram(host, port, buf[:n])
			if err != nil {
				continue
			}
			udpLn.WriteToUDP(packet, dst)
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		udpLn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, src, err := udpLn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			closeAll()
			break
		}
		setClient(src)

		host, port, payload, err := parseUDPDatagram(buf[:n])
		if err != nil {
			continue
		}
		upstream.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
		if _, err := upstream.WriteTo(payload, host, port); err != nil {
			continue
		}
	}
	<-done
}

func parseUDPDatagram(b []byte) (host string, port int, payload []byte, err error) {
	if len(b) < 3 {
		return "", 0, nil, errors.New("short udp datagram")
	}
	if b[0] != 0 || b[1] != 0 {
		return "", 0, nil, errors.New("invalid reserved bytes")
	}
	if b[2] != 0 {
		return "", 0, nil, errors.New("fragmentation not supported")
	}
	body := b[3:]
	br := bytes.NewReader(body)
	host, port, err = protocol.ReadAddress(br)
	if err != nil {
		return "", 0, nil, err
	}
	consumed := len(body) - br.Len()
	return host, port, body[consumed:], nil
}

func buildUDPDatagram(host string, port int, payload []byte) ([]byte, error) {
	addr, err := protocol.EncodeAddress(host, port)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(addr)+len(payload))
	out = append(out, 0, 0, 0)
	out = append(out, addr...)
	out = append(out, payload...)
	return out, nil
}

func writeUDPReply(conn net.Conn, ip net.IP, port int) error {
	enc, err := protocol.EncodeAddress(ip.String(), port)
	if err != nil {
		return err
	}
	out := make([]byte, 0, 3+len(enc))
	out = append(out, Version, RepSuccess, 0x00)
	out = append(out, enc...)
	_, err = conn.Write(out)
	return err
}
