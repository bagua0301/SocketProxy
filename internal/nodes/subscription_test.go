package nodes

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseURISIP002(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	uri := "ss://" + userinfo + "@1.2.3.4:8388#HK%20Node"

	n, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if n.Name != "HK Node" {
		t.Fatalf("name = %q", n.Name)
	}
	if n.Server != "1.2.3.4" || n.Port != 8388 {
		t.Fatalf("addr = %s:%d", n.Server, n.Port)
	}
	if n.Method != "aes-256-gcm" || n.Password != "secret" {
		t.Fatalf("credentials = %s/%s", n.Method, n.Password)
	}
	if !n.UDP {
		t.Fatal("expected UDP enabled by default")
	}
}

func TestParseURILegacy(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pass@5.6.7.8:8389"))
	n, err := ParseURI("ss://" + blob)
	if err != nil {
		t.Fatal(err)
	}
	if n.Server != "5.6.7.8" || n.Port != 8389 {
		t.Fatalf("addr = %s:%d", n.Server, n.Port)
	}
	if n.Method != "chacha20-ietf-poly1305" || n.Password != "pass" {
		t.Fatalf("credentials = %s/%s", n.Method, n.Password)
	}
}

func TestParseSubscriptionPlain(t *testing.T) {
	a := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:one")) + "@1.1.1.1:1001#a"
	b := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:two")) + "@2.2.2.2:1002#b"

	nodes, err := ParseSubscription([]byte(a + "\n" + b + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes", len(nodes))
	}
}

func TestParseSubscriptionBase64(t *testing.T) {
	a := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:one")) + "@1.1.1.1:1001#a"
	b := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:two")) + "@2.2.2.2:1002#b"
	blob := base64.StdEncoding.EncodeToString([]byte(a + "\n" + b))

	nodes, err := ParseSubscription([]byte(blob))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes", len(nodes))
	}
}

func TestParseSubscriptionInvalid(t *testing.T) {
	if _, err := ParseSubscription([]byte("garbage")); err == nil {
		t.Fatal("expected error for invalid subscription")
	}
}

func TestFetchSubscription(t *testing.T) {
	a := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:one")) + "@1.1.1.1:1001#a"
	b := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:two")) + "@2.2.2.2:1002#b"
	body := base64.StdEncoding.EncodeToString([]byte(a + "\n" + b))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	nodes, err := FetchSubscription(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes", len(nodes))
	}
}
