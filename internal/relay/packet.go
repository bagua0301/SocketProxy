package relay

import (
	"net"
	"time"
)

// PacketConn is an address-oriented packet connection used for UDP relaying.
// Unlike net.PacketConn, addresses are expressed as host/port pairs so that
// domains can be forwarded without local resolution.
type PacketConn interface {
	WriteTo(b []byte, host string, port int) (int, error)
	ReadFrom(b []byte) (n int, host string, port int, err error)
	LocalAddr() net.Addr
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}
