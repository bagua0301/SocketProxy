package nodes

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"socketproxy/internal/config"
)

// FetchSubscription downloads a subscription and parses its nodes.
func FetchSubscription(rawURL string, timeout time.Duration) ([]config.Node, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription http status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return ParseSubscription(data)
}

// ParseSubscription parses a subscription body. The body may be plain text
// containing ss:// URIs or a base64-encoded blob of the same.
func ParseSubscription(data []byte) ([]config.Node, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, errors.New("empty subscription")
	}
	if !strings.Contains(text, "ss://") {
		if decoded, err := decodeBase64(text); err == nil {
			text = string(decoded)
		}
	}

	var nodes []config.Node
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "ss://") {
			continue
		}
		n, err := ParseURI(line)
		if err != nil {
			continue
		}
		nodes = append(nodes, n)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, errors.New("no valid ss:// nodes in subscription")
	}
	return nodes, nil
}

// ParseURI parses a SIP002 ss:// URI.
func ParseURI(raw string) (config.Node, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ss://") {
		return config.Node{}, errors.New("not an ss:// uri")
	}
	rest := strings.TrimPrefix(raw, "ss://")

	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		if decoded, err := url.QueryUnescape(rest[i+1:]); err == nil {
			name = decoded
		} else {
			name = rest[i+1:]
		}
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return config.Node{}, errors.New("empty ss uri")
	}

	var method, password, hostport string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo := rest[:i]
		hostport = rest[i+1:]
		decoded, err := decodeBase64(userinfo)
		if err != nil {
			return config.Node{}, fmt.Errorf("decode userinfo: %w", err)
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return config.Node{}, errors.New("invalid userinfo")
		}
		method, password = parts[0], parts[1]
	} else {
		decoded, err := decodeBase64(rest)
		if err != nil {
			return config.Node{}, fmt.Errorf("decode ss uri: %w", err)
		}
		s := string(decoded)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return config.Node{}, errors.New("invalid ss uri")
		}
		parts := strings.SplitN(s[:at], ":", 2)
		if len(parts) != 2 {
			return config.Node{}, errors.New("invalid userinfo")
		}
		method, password = parts[0], parts[1]
		hostport = s[at+1:]
	}

	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return config.Node{}, fmt.Errorf("invalid host:port %q: %w", hostport, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return config.Node{}, fmt.Errorf("invalid port %q", portStr)
	}
	if method == "" || password == "" {
		return config.Node{}, errors.New("missing method or password")
	}
	if name == "" {
		name = net.JoinHostPort(host, portStr)
	}

	return config.Node{
		Name:     name,
		Server:   host,
		Port:     port,
		Password: password,
		Method:   method,
		UDP:      true,
		Timeout:  10,
	}, nil
}

func decodeBase64(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', ' ', '\t':
			return -1
		}
		return r
	}, s)

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		if b, err := enc.DecodeString(cleaned); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}
