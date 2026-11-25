package server

import (
	"testing"
	"time"
)

func TestReplayCacheRejectsDuplicate(t *testing.T) {
	c := NewReplayCache(time.Minute)
	salt := []byte("abcdefghijklmnop")

	if !c.Add(salt) {
		t.Fatal("first Add should succeed")
	}
	if c.Add(salt) {
		t.Fatal("duplicate Add should be rejected")
	}
}

func TestReplayCacheDifferentSalts(t *testing.T) {
	c := NewReplayCache(time.Minute)
	if !c.Add([]byte("salt-one")) {
		t.Fatal("first salt rejected")
	}
	if !c.Add([]byte("salt-two")) {
		t.Fatal("second salt rejected")
	}
}

func TestReplayCacheExpiry(t *testing.T) {
	c := NewReplayCache(10 * time.Millisecond)
	salt := []byte("salt")
	if !c.Add(salt) {
		t.Fatal("first Add failed")
	}
	time.Sleep(20 * time.Millisecond)
	if !c.Add(salt) {
		t.Fatal("salt should be accepted after TTL expiry")
	}
}
