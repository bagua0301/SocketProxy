package plugin

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func contains(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

func TestClientEnv(t *testing.T) {
	env := clientEnv("1.2.3.4", 8388, 1234, "tls;host=example.com")
	for _, want := range []string{
		"SS_REMOTE_HOST=1.2.3.4",
		"SS_REMOTE_PORT=8388",
		"SS_LOCAL_HOST=127.0.0.1",
		"SS_LOCAL_PORT=1234",
		"SS_PLUGIN_OPTIONS=tls;host=example.com",
	} {
		if !contains(env, want) {
			t.Fatalf("missing %q in %v", want, env)
		}
	}
}

func TestServerEnv(t *testing.T) {
	env := serverEnv("0.0.0.0", 443, "127.0.0.1", 9000, "server")
	for _, want := range []string{
		"SS_REMOTE_HOST=0.0.0.0",
		"SS_REMOTE_PORT=443",
		"SS_LOCAL_HOST=127.0.0.1",
		"SS_LOCAL_PORT=9000",
		"SS_PLUGIN_OPTIONS=server",
	} {
		if !contains(env, want) {
			t.Fatalf("missing %q in %v", want, env)
		}
	}
}

func TestFreePort(t *testing.T) {
	port, err := FreePort()
	if err != nil {
		t.Fatal(err)
	}
	if port <= 0 || port > 65535 {
		t.Fatalf("invalid port %d", port)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port %d not usable: %v", port, err)
	}
	ln.Close()
}

func TestStartMissingCommand(t *testing.T) {
	if _, _, err := StartClient("socketproxy-no-such-plugin-xyz", "127.0.0.1", 1, "", nil, 2*time.Second); err == nil {
		t.Fatal("expected error for missing plugin command")
	}
}

func TestResolveExecutableMissing(t *testing.T) {
	if _, err := resolveExecutable("socketproxy-no-such-plugin-xyz"); err == nil {
		t.Fatal("expected error for command not in PATH")
	}
	missing := filepath.Join(t.TempDir(), "missing-plugin.exe")
	if _, err := resolveExecutable(missing); err == nil {
		t.Fatal("expected error for missing explicit path")
	}
}
