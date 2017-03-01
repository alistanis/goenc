// Package gcm supports gcm encryption - gcm is authenticated by default
package gcm

// https://en.wikipedia.org/wiki/Galois/Counter_Mode

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
)

// NonceSize // generic NonceSize from RFC5084
const NonceSize = 12 // https://tools.ietf.org/html/rfc5084

// KeySize // generic KeySize
const KeySize = generate.KeySize

// Cipher to implement the BlockCipher interface
type Cipher struct {
	NonceSize int
}

// New returns a new GCM cipher
func New() *Cipher {
	return &Cipher{NonceSize: NonceSize}
}

// Encrypt implements the BlockCipher interface
func (c *Cipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	return Encrypt(key, plaintext, c.NonceSize)
}

// Decrypt implements the BlockCipher interface
func (c *Cipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	return Decrypt(key, ciphertext, c.NonceSize)
}

// KeySize returns the GCM key size
func (c *Cipher) KeySize() int {
	return KeySize
}

// EncryptWithID calls the package EncryptWithID and passes c.NonceSize
func (c *Cipher) EncryptWithID(key, plaintext []byte, sender uint32) ([]byte, error) {
	return EncryptWithID(key, plaintext, sender, c.NonceSize)
}

// DecryptWithID calls the package DecryptWithID and passes c.NonceSize
func (c *Cipher) DecryptWithID(message []byte, k KeyRetriever) ([]byte, error) {
	return DecryptWithID(message, k, c.NonceSize)
}

// Encrypt secures a message using AES-GCM.
func Encrypt(key, plaintext []byte, nonceSize int) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, nonceSize)
	if err != nil {
		return nil, err
	}

	nonce, err := generate.GCMNonce()
	if err != nil {
		return nil, err
	}

	// Seal will append the output to the first argument; the usage
	// here appends the ciphertext to the nonce. The final parameter
	// is any additional data to be authenticated.
	out := gcm.Seal(nonce[:], nonce[:], plaintext, nil)
	return out, nil
}

// EncryptString is a convenience function for working with strings
func EncryptString(key, plaintext string, nonceSize int) (string, error) {
	data, err := Encrypt([]byte(key), []byte(plaintext), nonceSize)
	return string(data), err
}

// Decrypt decrypts data using AES-GCM
func Decrypt(key, ciphertext []byte, nonceSize int) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, encerrors.ErrInvalidMessageLength
	}
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	copy(nonce, ciphertext)
	return gcm.Open(nil, nonce[:], ciphertext[nonceSize:], nil)
}

// DecryptString is a convenience function for working with strings
func DecryptString(key, ciphertext string, nonceSize int) (string, error) {
	data, err := Decrypt([]byte(key), []byte(ciphertext), nonceSize)
	return string(data), err
}

//---------------------------------------------
// For use with more complex encryption schemes
//---------------------------------------------

// EncryptWithID secures a message and prepends a 4-byte sender ID
// to the message. The end bit is tricky, because gcm.Seal modifies buf, and this is necessary
func EncryptWithID(key, message []byte, sender uint32, nonceSize int) ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, sender)

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, nonceSize)
	if err != nil {
		return nil, err
	}

	nonce, err := generate.GCMNonce()
	if err != nil {
		return nil, err
	}

	buf = append(buf, nonce[:]...)
	return gcm.Seal(buf, nonce[:], message, buf[:4]), nil
}

// EncryptStringWithID is a helper function to work with strings instead of bytes
func EncryptStringWithID(key, message string, sender uint32, nonceSize int) (string, error) {
	data, err := EncryptWithID([]byte(key), []byte(message), sender, nonceSize)
	return string(data), err
}

// DecryptWithID takes an encrypted message and a KeyForID function (to get a key from a cache or a database perhaps)
// It checks the first 4 bytes for prepended header data, in this case, a sender ID
func DecryptWithID(message []byte, k KeyRetriever, nonceSize int) ([]byte, error) {

	if len(message) <= nonceSize+4 {
		return nil, encerrors.ErrInvalidMessageLength
	}

	id := binary.BigEndian.Uint32(message[:4])
	key, err := k.KeyForID(id)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, nonceSize)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	copy(nonce, message[4:])

	ciphertext := message[4+nonceSize:]

	// Decrypt the message, using the sender ID as the additional
	// data requiring authentication.
	out, err := gcm.Open(nil, nonce, ciphertext, message[:4])
	if err != nil {
		return nil, err
	}

	return out, nil
}

// DecryptStringWithID is a helper function to work with strings instead of bytes
func DecryptStringWithID(message string, k KeyRetriever, nonceSize int) (string, error) {
	data, err := DecryptWithID([]byte(message), k, nonceSize)
	return string(data), err
}

// KeyRetriever represents a type that should be used in order to retrieve a key from a datastore
type KeyRetriever interface {
	KeyForID(uint32) ([]byte, error)
}

// GCMHelper is designed to make it easy to call EncryptWithID and DecryptWithID by assigning the KeyForIDFunc
// it implements KeyRetriever and provides convenience functions
// It also serves as an example for how to use KeyRetriever
type GCMHelper struct {
	KeyForIDFunc func(uint32) ([]byte, error)
}

// NewGCMHelper returns a new helper
func NewGCMHelper(f func(uint32) ([]byte, error)) *GCMHelper {
	return &GCMHelper{f}
}

// KeyForID implements the KeyRetriever interface, it should be used to get a Key for the given ID
func (h *GCMHelper) KeyForID(u uint32) ([]byte, error) {
	return h.KeyForIDFunc(u)
}
