package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// EncodeAddress encodes host/port using the SOCKS5 address format:
// ATYP + address + 2-byte big-endian port.
func EncodeAddress(host string, port int) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf := make([]byte, 1+net.IPv4len+2)
			buf[0] = AddrTypeIPv4
			copy(buf[1:], v4)
			binary.BigEndian.PutUint16(buf[1+net.IPv4len:], uint16(port))
			return buf, nil
		}
		buf := make([]byte, 1+net.IPv6len+2)
		buf[0] = AddrTypeIPv6
		copy(buf[1:], ip.To16())
		binary.BigEndian.PutUint16(buf[1+net.IPv6len:], uint16(port))
		return buf, nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("invalid domain length %d", len(host))
	}
	buf := make([]byte, 1+1+len(host)+2)
	buf[0] = AddrTypeDomain
	buf[1] = byte(len(host))
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+len(host):], uint16(port))
	return buf, nil
}

// ReadAddress reads a SOCKS5-formatted address from r.
func ReadAddress(r io.Reader) (host string, port int, err error) {
	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case AddrTypeIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err = io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case AddrTypeIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err = io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case AddrTypeDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(l[0]))
		if _, err = io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	default:
		return "", 0, fmt.Errorf("unsupported address type 0x%02x", atyp[0])
	}
	var portBuf [2]byte
	if _, err = io.ReadFull(r, portBuf[:]); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBuf[:])), nil
}
