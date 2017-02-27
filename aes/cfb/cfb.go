// Package cfb supports basic cfb encryption with NO HMAC
package cfb

// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_.28CFB.29

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
)

// KeySize for CFB uses the generic key size
const KeySize = generate.KeySize

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

// Decrypt decrypts ciphertext using the given key
func Decrypt(key, ciphertext []byte) ([]byte, error) {

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, encerrors.ErrInvalidMessageLength
	}

	// get first 16 bytes from ciphertext
	iv := ciphertext[:aes.BlockSize]

	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]

	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)

	// SimpleDecrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Encrypt encrypts ciphertext using the given key.
// NOTE: This is not secure without being authenticated (crypto/hmac)
func Encrypt(key, plaintext []byte) ([]byte, error) {
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Empty array of 16 + plaintext length
	// Include the IV at the beginning
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// Slice of first 16 bytes
	iv := ciphertext[:aes.BlockSize]

	// Write 16 rand bytes to fill iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Return an encrypted stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// SimpleEncrypt bytes from plaintext to ciphertext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
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
