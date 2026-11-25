package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MethodAES128GCM        = "aes-128-gcm"
	MethodAES256GCM        = "aes-256-gcm"
	MethodChaCha20Poly1305 = "chacha20-ietf-poly1305"
)

// Method describes a Shadowsocks AEAD cipher method.
type Method interface {
	Name() string
	KeySize() int
	SaltSize() int
	NewAEAD(key []byte) (stdcipher.AEAD, error)
}

type aesMethod struct {
	name    string
	keySize int
}

func (m aesMethod) Name() string  { return m.name }
func (m aesMethod) KeySize() int  { return m.keySize }
func (m aesMethod) SaltSize() int { return m.keySize }

func (m aesMethod) NewAEAD(key []byte) (stdcipher.AEAD, error) {
	if len(key) != m.keySize {
		return nil, fmt.Errorf("%s: invalid key length %d", m.name, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return stdcipher.NewGCM(block)
}

type chachaMethod struct{}

func (chachaMethod) Name() string  { return MethodChaCha20Poly1305 }
func (chachaMethod) KeySize() int  { return chacha20poly1305.KeySize }
func (chachaMethod) SaltSize() int { return chacha20poly1305.KeySize }

func (chachaMethod) NewAEAD(key []byte) (stdcipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%s: invalid key length %d", MethodChaCha20Poly1305, len(key))
	}
	return chacha20poly1305.New(key)
}

var registry = map[string]Method{
	MethodAES128GCM:        aesMethod{name: MethodAES128GCM, keySize: 16},
	MethodAES256GCM:        aesMethod{name: MethodAES256GCM, keySize: 32},
	MethodChaCha20Poly1305: chachaMethod{},
}

// FromName returns the cipher method registered under name.
func FromName(name string) (Method, error) {
	m, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unsupported cipher method %q", name)
	}
	return m, nil
}

// Names returns the supported cipher method names.
func Names() []string {
	return []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305}
}
