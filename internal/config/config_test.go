package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStripJSONComments(t *testing.T) {
	in := []byte(`{
  // line comment
  "url": "http://example.com/path", /* block comment */
  "n": 1
}`)
	var m map[string]any
	if err := json.Unmarshal(stripJSONComments(in), &m); err != nil {
		t.Fatal(err)
	}
	if m["url"] != "http://example.com/path" {
		t.Fatalf("url = %v", m["url"])
	}
	if m["n"].(float64) != 1 {
		t.Fatalf("n = %v", m["n"])
	}
}

func TestLoadClientWithComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	content := `{
  // local socks5
  "listen": "127.0.0.1:1080",
  "strategy": "manual",
  /*
    node list
  */
  "nodes": [
    {
      "name": "a",
      "server": "1.1.1.1",
      "port": 8388,
      "password": "p",
      "method": "aes-128-gcm"
    }
  ]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:1080" || len(cfg.Nodes) != 1 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestExampleConfigsLoadable(t *testing.T) {
	clientPath := filepath.Join("..", "..", "configs", "client.plugin.example.json")
	if _, err := os.Stat(clientPath); err == nil {
		if _, err := LoadClient(clientPath); err != nil {
			t.Fatalf("client example: %v", err)
		}
	}

	serverPath := filepath.Join("..", "..", "configs", "server.plugin.example.json")
	if _, err := os.Stat(serverPath); err == nil {
		if _, err := LoadServer(serverPath); err != nil {
			t.Fatalf("server example: %v", err)
		}
	}
}
