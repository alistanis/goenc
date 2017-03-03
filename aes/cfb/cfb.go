// Package cfb supports basic cfb encryption with NO HMAC
package cfb

// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_.28CFB.29

import (
	"crypto/aes"
	"crypto/cipher"

	"crypto/hmac"
	"crypto/sha256"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
)

const (
	// KeySize for CFB uses the generic key size
	KeySize = generate.KeySize
	// CKeySize - Cipher key size - AES-256
	CKeySize = 32
	// MACSize is the output size of HMAC-SHA-256
	MACSize = 32
	// MKeySize - HMAC key size - HMAC-SHA-256
	MKeySize = 32
	// IVSize - 16 for cfb
	IVSize = 16
)

// Cipher to use for implementing the BlockCipher interface
type Cipher struct {
}

// New returns a new cfb cipher
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

// Encrypt encrypts plaintext using the given key with CTR encryption
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, encerrors.ErrInvalidKeyLength
	}

	iv, err := generate.RandBytes(IVSize)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(plaintext))

	// NewCipher only returns an error with an invalid key size,
	// but the key size was checked at the beginning of the function.
	c, _ := aes.NewCipher(key[:CKeySize])
	cbc := cipher.NewCFBEncrypter(c, iv)
	cbc.XORKeyStream(ct, plaintext)

	h := hmac.New(sha256.New, key[CKeySize:])
	ct = append(iv, ct...)
	h.Write(ct)
	ct = h.Sum(ct)
	return ct, nil
}

// Decrypt decrypts ciphertext using the given key
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, encerrors.ErrInvalidKeyLength
	}

	if len(ciphertext) <= (IVSize + MACSize) {
		return nil, encerrors.ErrInvalidMessageLength
	}

	macStart := len(ciphertext) - MACSize
	tag := ciphertext[macStart:]
	out := make([]byte, macStart-IVSize)
	ciphertext = ciphertext[:macStart]

	h := hmac.New(sha256.New, key[CKeySize:])
	h.Write(ciphertext)
	mac := h.Sum(nil)
	if !hmac.Equal(mac, tag) {
		return nil, encerrors.ErrInvalidSum
	}

	c, _ := aes.NewCipher(key[:CKeySize])
	cbc := cipher.NewCFBDecrypter(c, ciphertext[:IVSize])
	cbc.XORKeyStream(out, ciphertext[IVSize:])
	return out, nil
}

// DecryptString decrypts ciphertext using the given key
func DecryptString(key, ciphertext string) (string, error) {
	b, err := Decrypt([]byte(key), []byte(ciphertext))
	return string(b), err
}

// EncryptString encrypts ciphertext using the given key
func EncryptString(key, plaintext string) (string, error) {
	b, err := Encrypt([]byte(key), []byte(plaintext))
	return string(b), err
}
