package relay

import (
	"io"
	"net"
	"sync"
)

type closeWriter interface {
	CloseWrite() error
}

// Relay copies data in both directions between a and b until both directions
// finish, then closes both connections.
func Relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipe(b, a)
	}()
	go func() {
		defer wg.Done()
		pipe(a, b)
	}()
	wg.Wait()
	a.Close()
	b.Close()
}

func pipe(dst, src net.Conn) {
	io.Copy(dst, src)
	if cw, ok := dst.(closeWriter); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
}
