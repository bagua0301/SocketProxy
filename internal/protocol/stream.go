package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	stdcipher "crypto/cipher"

	spcipher "socketproxy/internal/cipher"
	spcrypto "socketproxy/internal/crypto"
)

// maxPayload is the maximum plaintext size of a single AEAD chunk.
const maxPayload = 0x3FFF

func incNonce(nonce *[12]byte) {
	for i := 0; i < len(nonce); i++ {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// Writer encrypts a Shadowsocks AEAD TCP stream. The salt is written to the
// underlying writer on construction.
type Writer struct {
	w     io.Writer
	aead  stdcipher.AEAD
	nonce [12]byte
}

// NewWriter creates a Writer, generating and writing a random salt.
func NewWriter(w io.Writer, method spcipher.Method, masterKey []byte) (*Writer, error) {
	salt := make([]byte, method.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	if _, err := w.Write(salt); err != nil {
		return nil, fmt.Errorf("write salt: %w", err)
	}
	subkey := spcrypto.Subkey(masterKey, salt, method.KeySize())
	aead, err := method.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}
	return &Writer{w: w, aead: aead}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPayload {
			n = maxPayload
		}
		if err := w.writeChunk(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (w *Writer) writeChunk(p []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))

	header := w.aead.Seal(nil, w.nonce[:], lenBuf[:], nil)
	incNonce(&w.nonce)

	payload := w.aead.Seal(nil, w.nonce[:], p, nil)
	incNonce(&w.nonce)

	buf := make([]byte, 0, len(header)+len(payload))
	buf = append(buf, header...)
	buf = append(buf, payload...)
	_, err := w.w.Write(buf)
	return err
}

// Reader decrypts a Shadowsocks AEAD TCP stream. The salt is read from the
// underlying reader on construction.
type Reader struct {
	r     io.Reader
	aead  stdcipher.AEAD
	nonce [12]byte
	buf   []byte
}

// NewReader reads the salt from r and creates a Reader.
func NewReader(r io.Reader, method spcipher.Method, masterKey []byte) (*Reader, error) {
	salt := make([]byte, method.SaltSize())
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	return NewReaderWithSalt(r, method, masterKey, salt)
}

// NewReaderWithSalt creates a Reader using an already-read salt. This lets the
// caller inspect the salt (e.g. for replay protection) before decrypting.
func NewReaderWithSalt(r io.Reader, method spcipher.Method, masterKey, salt []byte) (*Reader, error) {
	if len(salt) != method.SaltSize() {
		return nil, fmt.Errorf("invalid salt length %d", len(salt))
	}
	subkey := spcrypto.Subkey(masterKey, salt, method.KeySize())
	aead, err := method.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}
	return &Reader{r: r, aead: aead}, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if err := r.readChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *Reader) readChunk() error {
	overhead := r.aead.Overhead()

	header := make([]byte, 2+overhead)
	if _, err := io.ReadFull(r.r, header); err != nil {
		return err
	}
	plain, err := r.aead.Open(nil, r.nonce[:], header, nil)
	if err != nil {
		return fmt.Errorf("decrypt chunk length: %w", err)
	}
	incNonce(&r.nonce)

	length := int(binary.BigEndian.Uint16(plain))
	if length > maxPayload {
		return fmt.Errorf("chunk length %d exceeds maximum %d", length, maxPayload)
	}

	payload := make([]byte, length+overhead)
	if _, err := io.ReadFull(r.r, payload); err != nil {
		return err
	}
	data, err := r.aead.Open(nil, r.nonce[:], payload, nil)
	if err != nil {
		return fmt.Errorf("decrypt chunk payload: %w", err)
	}
	incNonce(&r.nonce)

	r.buf = data
	return nil
}
