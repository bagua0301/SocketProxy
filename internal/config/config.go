package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/route"
)

const (
	DefaultListen        = "127.0.0.1:1080"
	DefaultServerListen  = "0.0.0.0:8388"
	DefaultNodeTimeout   = 10 * time.Second
	DefaultServerTimeout = 120 * time.Second
)

type Node struct {
	Name       string   `json:"name"`
	Server     string   `json:"server"`
	Port       int      `json:"port"`
	Password   string   `json:"password"`
	Method     string   `json:"method"`
	UDP        bool     `json:"udp"`
	Timeout    int      `json:"timeout"`
	Plugin     string   `json:"plugin"`
	PluginOpts string   `json:"pluginOpts"`
	PluginArgs []string `json:"pluginArgs"`
}

type HealthCheck struct {
	Interval int `json:"interval"`
	Timeout  int `json:"timeout"`
}

type Subscription struct {
	URL            string `json:"url"`
	UpdateInterval int    `json:"updateInterval"`
}

type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ClientConfig struct {
	Listen             string        `json:"listen"`
	Mode               string        `json:"mode"`
	DirectTimeout      int           `json:"directTimeout"`
	DisableSystemProxy bool          `json:"disableSystemProxy"`
	Strategy           string        `json:"strategy"`
	Node               string        `json:"node"`
	Nodes              []Node        `json:"nodes"`
	Auth               *Auth         `json:"auth,omitempty"`
	HealthCheck        *HealthCheck  `json:"healthCheck,omitempty"`
	Subscription       *Subscription `json:"subscription,omitempty"`
}

type ServerConfig struct {
	Listen     string   `json:"listen"`
	UDPListen  string   `json:"udpListen"`
	DisableUDP bool     `json:"disableUDP"`
	Method     string   `json:"method"`
	Password   string   `json:"password"`
	Timeout    int      `json:"timeout"`
	Plugin     string   `json:"plugin"`
	PluginOpts string   `json:"pluginOpts"`
	PluginArgs []string `json:"pluginArgs"`
}

func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	var cfg ClientConfig
	if err := json.Unmarshal(stripJSONComments(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse client config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config: %w", err)
	}
	var cfg ServerConfig
	if err := json.Unmarshal(stripJSONComments(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse server config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *ClientConfig) normalize() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Auth != nil && c.Auth.Username == "" {
		return errors.New("client config: auth.username is required")
	}
	if c.Mode == "" {
		c.Mode = route.ModeAuto
	}
	if !route.ValidMode(c.Mode) {
		return fmt.Errorf("client config: invalid mode %q", c.Mode)
	}
	if c.DirectTimeout < 0 {
		return fmt.Errorf("client config: invalid directTimeout %d", c.DirectTimeout)
	}
	if len(c.Nodes) == 0 {
		return errors.New("client config: at least one node is required")
	}
	for i := range c.Nodes {
		if err := c.Nodes[i].normalize(i); err != nil {
			return err
		}
	}
	if c.Node != "" {
		if _, err := c.SelectNode(c.Node); err != nil {
			return err
		}
	}
	return nil
}

func (c *ClientConfig) SelectNode(name string) (Node, error) {
	if len(c.Nodes) == 0 {
		return Node{}, errors.New("no nodes configured")
	}
	want := name
	if want == "" {
		want = c.Node
	}
	if want == "" {
		return c.Nodes[0], nil
	}
	for _, n := range c.Nodes {
		if n.Name == want {
			return n, nil
		}
	}
	return Node{}, fmt.Errorf("node %q not found", want)
}

func (n *Node) normalize(index int) error {
	if n.Name == "" {
		n.Name = fmt.Sprintf("node-%d", index)
	}
	if n.Server == "" {
		return fmt.Errorf("node %q: server is required", n.Name)
	}
	if n.Port < 1 || n.Port > 65535 {
		return fmt.Errorf("node %q: invalid port %d", n.Name, n.Port)
	}
	if n.Password == "" {
		return fmt.Errorf("node %q: password is required", n.Name)
	}
	if n.Method == "" {
		return fmt.Errorf("node %q: method is required", n.Name)
	}
	if _, err := cipher.FromName(n.Method); err != nil {
		return fmt.Errorf("node %q: %w", n.Name, err)
	}
	if n.Timeout < 0 {
		return fmt.Errorf("node %q: invalid timeout %d", n.Name, n.Timeout)
	}
	return nil
}

func (n Node) DialTimeout() time.Duration {
	if n.Timeout <= 0 {
		return DefaultNodeTimeout
	}
	return time.Duration(n.Timeout) * time.Second
}

func (c *ServerConfig) normalize() error {
	if c.Listen == "" {
		c.Listen = DefaultServerListen
	}
	if c.UDPListen == "" {
		c.UDPListen = c.Listen
	}
	if c.Method == "" {
		return errors.New("server config: method is required")
	}
	if _, err := cipher.FromName(c.Method); err != nil {
		return err
	}
	if c.Password == "" {
		return errors.New("server config: password is required")
	}
	if c.Timeout < 0 {
		return fmt.Errorf("server config: invalid timeout %d", c.Timeout)
	}
	return nil
}

func (c ServerConfig) TimeoutDuration() time.Duration {
	if c.Timeout <= 0 {
		return DefaultServerTimeout
	}
	return time.Duration(c.Timeout) * time.Second
}

func (c ServerConfig) UDPListenAddr() string {
	if c.DisableUDP {
		return ""
	}
	return c.UDPListen
}

func (c ClientConfig) DirectTimeoutDuration() time.Duration {
	if c.DirectTimeout <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.DirectTimeout) * time.Second
}

// stripJSONComments removes // line comments and /* */ block comments that are
// not inside JSON strings, allowing self-documenting config files.
func stripJSONComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false

	for i := 0; i < len(data); i++ {
		c := data[i]

		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}

		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}

		if c == '/' && i+1 < len(data) {
			switch data[i+1] {
			case '/':
				i += 2
				for i < len(data) && data[i] != '\n' {
					i++
				}
				continue
			case '*':
				i += 2
				for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
					i++
				}
				i++
				continue
			}
		}

		out = append(out, c)
	}
	return out
}
