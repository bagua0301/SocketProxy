// Package route chooses between a direct connection and the proxy.
package route

import (
	"errors"
	"net"
	"sync"
	"time"
)

// directFailTTL is how long a target that failed a direct dial is remembered
// so subsequent connections go straight to the proxy.
const directFailTTL = 10 * time.Minute

const (
	// ModeAuto tries a direct connection first and falls back to the proxy.
	ModeAuto = "auto"
	// ModeProxy always goes through the proxy.
	ModeProxy = "proxy"
	// ModeDirect always connects directly.
	ModeDirect = "direct"
)

func ValidMode(mode string) bool {
	switch mode {
	case ModeAuto, ModeProxy, ModeDirect:
		return true
	}
	return false
}

// DialFunc opens a connection to target ("host:port").
type DialFunc func(target string) (net.Conn, error)

// Dialer routes connections according to Mode.
type Dialer struct {
	Proxy         DialFunc
	Mode          string
	DirectTimeout time.Duration
	Logf          func(format string, args ...any)

	dialDirect func(target string, timeout time.Duration) (net.Conn, error)

	mu     sync.Mutex
	failed map[string]time.Time
}

func (d *Dialer) timeout() time.Duration {
	if d.DirectTimeout > 0 {
		return d.DirectTimeout
	}
	return 5 * time.Second
}

func (d *Dialer) dial(target string) (net.Conn, error) {
	if d.dialDirect != nil {
		return d.dialDirect(target, d.timeout())
	}
	return net.DialTimeout("tcp", target, d.timeout())
}

func (d *Dialer) directFailedRecently(target string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if at, ok := d.failed[target]; ok {
		if time.Since(at) < directFailTTL {
			return true
		}
		delete(d.failed, target)
	}
	return false
}

func (d *Dialer) markDirectFailed(target string) {
	d.mu.Lock()
	if d.failed == nil {
		d.failed = make(map[string]time.Time)
	}
	d.failed[target] = time.Now()
	d.mu.Unlock()
}

func (d *Dialer) Dial(target string) (net.Conn, error) {
	switch d.Mode {
	case ModeDirect:
		return d.dial(target)

	case ModeAuto:
		if d.directFailedRecently(target) {
			if d.Logf != nil {
				d.Logf("direct skipped (recent failure), using proxy: %s", target)
			}
			if d.Proxy == nil {
				return nil, errors.New("route: proxy dialer is nil")
			}
			return d.Proxy(target)
		}

		conn, err := d.dial(target)
		if err == nil {
			if d.Logf != nil {
				d.Logf("direct: %s", target)
			}
			return conn, nil
		}
		d.markDirectFailed(target)
		if d.Logf != nil {
			d.Logf("direct failed (%v), using proxy: %s", err, target)
		}
		if d.Proxy == nil {
			return nil, err
		}
		return d.Proxy(target)

	default:
		if d.Proxy == nil {
			return nil, errors.New("route: proxy dialer is nil")
		}
		return d.Proxy(target)
	}
}
