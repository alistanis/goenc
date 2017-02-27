// Package ctr supports ctr encryption
package ctr

// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"io"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
)

const (
	// NonceSize to use for nonces
	NonceSize = aes.BlockSize
	// MACSize is the output size of HMAC-SHA-256
	MACSize = 32
	// CKeySize - Cipher key size - AES-256
	CKeySize = 32
	// MKeySize - HMAC key size - HMAC-SHA-256
	MKeySize = 32
	// KeySize to use for keys, 64 bytes
	KeySize = CKeySize + MKeySize
)

// Cipher to implement the BlockCipher interface
type Cipher struct {
}

// New returns a new ctr cipher
func New() *Cipher {
	return &Cipher{}
}

// Encrypt implements the BlockCipher interface
func (c *Cipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	return Encrypt(key, plaintext)
}

// Decrypt implements the BlockCipher interface
func (c *Cipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	return Decrypt(key, ciphertext)
}

// KeySize implements the BlockCipher interface
func (c *Cipher) KeySize() int {
	return KeySize
}

// Key returns a pointer to an array of bytes with the given KeySize
func Key() (*[KeySize]byte, error) {
	key := new([KeySize]byte)
	_, err := io.ReadFull(rand.Reader, key[:])
	return key, err
}

// Encrypt encrypts plaintext using the given key with CTR encryption
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, encerrors.ErrInvalidKeyLength
	}

	nonce, err := generate.RandBytes(NonceSize)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(plaintext))

	// NewCipher only returns an error with an invalid key size,
	// but the key size was checked at the beginning of the function.
	c, _ := aes.NewCipher(key[:CKeySize])
	ctr := cipher.NewCTR(c, nonce)
	ctr.XORKeyStream(ct, plaintext)

	h := hmac.New(sha256.New, key[CKeySize:])
	ct = append(nonce, ct...)
	h.Write(ct)
	ct = h.Sum(ct)
	return ct, nil
}

// Decrypt decrypts ciphertext using the given key
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, encerrors.ErrInvalidKeyLength
	}

	if len(ciphertext) <= (NonceSize + MACSize) {
		return nil, encerrors.ErrInvalidMessageLength
	}

	macStart := len(ciphertext) - MACSize
	tag := ciphertext[macStart:]
	out := make([]byte, macStart-NonceSize)
	ciphertext = ciphertext[:macStart]

	h := hmac.New(sha256.New, key[CKeySize:])
	h.Write(ciphertext)
	mac := h.Sum(nil)
	if !hmac.Equal(mac, tag) {
		return nil, encerrors.ErrInvalidSum
	}

	c, _ := aes.NewCipher(key[:CKeySize])
	ctr := cipher.NewCTR(c, ciphertext[:NonceSize])
	ctr.XORKeyStream(out, ciphertext[NonceSize:])
	return out, nil
}
