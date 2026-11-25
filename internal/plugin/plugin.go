// Package plugin integrates SIP003-style Shadowsocks plugins such as
// v2ray-plugin or simple-obfs.
package plugin

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Process is a running plugin subprocess.
type Process struct {
	command string
	cmd     *exec.Cmd
	addr    string

	mu     sync.Mutex
	closed bool
}

// Addr returns the local address the plugin listens on.
func (p *Process) Addr() string { return p.addr }

// Close terminates the plugin process.
func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	p.closed = true
	return p.cmd.Process.Kill()
}

// FreePort returns a currently free local TCP port.
func FreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func clientEnv(remoteHost string, remotePort, localPort int, opts string) []string {
	return []string{
		"SS_REMOTE_HOST=" + remoteHost,
		"SS_REMOTE_PORT=" + strconv.Itoa(remotePort),
		"SS_LOCAL_HOST=127.0.0.1",
		"SS_LOCAL_PORT=" + strconv.Itoa(localPort),
		"SS_PLUGIN_OPTIONS=" + opts,
	}
}

func serverEnv(publicHost string, publicPort int, localHost string, localPort int, opts string) []string {
	return []string{
		"SS_REMOTE_HOST=" + publicHost,
		"SS_REMOTE_PORT=" + strconv.Itoa(publicPort),
		"SS_LOCAL_HOST=" + localHost,
		"SS_LOCAL_PORT=" + strconv.Itoa(localPort),
		"SS_PLUGIN_OPTIONS=" + opts,
	}
}

// StartClient launches a SIP003 client-mode plugin that listens on a local
// port and tunnels to the Shadowsocks server at remoteHost:remotePort. It
// returns the process and the local address to dial.
func StartClient(command, remoteHost string, remotePort int, opts string, args []string, timeout time.Duration) (*Process, string, error) {
	if command == "" {
		return nil, "", errors.New("plugin: empty command")
	}
	localPort, err := FreePort()
	if err != nil {
		return nil, "", err
	}
	localAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
	proc, err := start(command, args, clientEnv(remoteHost, remotePort, localPort, opts), localAddr, timeout)
	if err != nil {
		return nil, "", err
	}
	return proc, localAddr, nil
}

// StartServer launches a SIP003 server-mode plugin that listens publicly on
// publicHost:publicPort and forwards to the Shadowsocks server listening on
// localHost:localPort.
func StartServer(command, publicHost string, publicPort int, localHost string, localPort int, opts string, args []string, timeout time.Duration) (*Process, error) {
	if command == "" {
		return nil, errors.New("plugin: empty command")
	}
	probeHost := publicHost
	if probeHost == "" || probeHost == "0.0.0.0" || probeHost == "::" {
		probeHost = "127.0.0.1"
	}
	probeAddr := net.JoinHostPort(probeHost, strconv.Itoa(publicPort))
	return start(command, args, serverEnv(publicHost, publicPort, localHost, localPort, opts), probeAddr, timeout)
}

func start(command string, args, env []string, waitAddr string, timeout time.Duration) (*Process, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	resolved, err := resolveExecutable(command)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(resolved, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("plugin: start %q: %w", command, err)
	}

	proc := &Process{command: command, cmd: cmd, addr: waitAddr}
	if err := waitListening(waitAddr, timeout); err != nil {
		proc.Close()
		return nil, fmt.Errorf("plugin %q did not listen on %s: %w", command, waitAddr, err)
	}
	return proc, nil
}

func resolveExecutable(command string) (string, error) {
	if command == "" {
		return "", errors.New("plugin: empty command")
	}
	if strings.ContainsAny(command, `/\`) {
		if _, err := os.Stat(command); err != nil {
			return "", fmt.Errorf("plugin executable %q not found: %w", command, err)
		}
		return command, nil
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return "", fmt.Errorf("plugin %q not found in PATH; install it or set \"plugin\" to the full path of the executable", command)
	}
	return path, nil
}

func waitListening(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(100 * time.Millisecond)
	}
}
