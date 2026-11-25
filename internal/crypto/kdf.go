package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
)

const hkdfInfo = "ss-subkey"

// EVPBytesToKey derives a master key from a password using OpenSSL's
// EVP_BytesToKey with MD5 and no salt, matching the Shadowsocks key
// derivation scheme.
func EVPBytesToKey(password string, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}
	pw := []byte(password)
	key := make([]byte, 0, keyLen+md5.Size)
	var prev []byte
	for len(key) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(pw)
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:keyLen]
}

// Subkey derives a session subkey from the master key and salt using
// HKDF-SHA1 with info "ss-subkey" (Shadowsocks AEAD, SIP004).
func Subkey(masterKey, salt []byte, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}
	// HKDF-Extract: PRK = HMAC-SHA1(salt, IKM)
	extract := hmac.New(sha1.New, salt)
	extract.Write(masterKey)
	prk := extract.Sum(nil)

	// HKDF-Expand
	out := make([]byte, 0, keyLen+sha1.Size)
	var prev []byte
	for i := byte(1); len(out) < keyLen; i++ {
		expand := hmac.New(sha1.New, prk)
		expand.Write(prev)
		expand.Write([]byte(hkdfInfo))
		expand.Write([]byte{i})
		prev = expand.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}
