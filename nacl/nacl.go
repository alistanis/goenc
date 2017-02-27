// Package nacl provides encryption by salting a key with a pad
// work is derived from:
//
// https://github.com/andmarios/golang-nacl-secretbox
package nacl

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/alistanis/goenc/generate"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize   = 32
	nonceSize = 24
)

// Cipher to implmement the BlockCipher interface
type Cipher struct {
	Pad []byte
}

// Encrypt implements the BlockCipher interface
func (c *Cipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	return Encrypt(c.Pad, key, plaintext)
}

// Decrypt implements the BlockCipher interface
func (c *Cipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	return Decrypt(c.Pad, key, ciphertext)
}

// KeySize returns the NaCL keysize
func (c *Cipher) KeySize() int {
	return keySize
}

// Encrypt salts a key using pad and encrypts a message
func Encrypt(pad, key, message []byte) (out []byte, err error) {
	if len(pad) < 32 {
		return nil, fmt.Errorf("pad had a length of %d, it must be at least 32 bytes", len(pad))
	}
	// NaCl's key has a constant size of 32 bytes.
	// The user provided key probably is less than that. We pad it with
	// a long enough string and truncate anything we don't need later on.
	key = append(key, pad...)

	// NaCl's key should be of type [32]byte.
	// Here we create it and truncate key bytes beyond 32
	naclKey := new([keySize]byte)
	copy(naclKey[:], key[:keySize])

	nonce, err := generate.Nonce()
	if err != nil {
		return nil, err
	}
	// out will hold the nonce and the encrypted message (ciphertext)
	out = make([]byte, nonceSize)
	// Copy the nonce to the start of out
	copy(out, nonce[:])
	// SimpleEncrypt the message and append it to out, assign the result to out
	out = secretbox.Seal(out, message, nonce, naclKey)
	return out, err
}

// Decrypt salts a key using pad and decrypts a message
func Decrypt(pad, key, data []byte) (out []byte, err error) {
	key = append(key, pad...)

	// NaCl's key should be of type [32]byte.
	// Here we create it and truncate key bytes beyond 32
	naclKey := new([keySize]byte)
	copy(naclKey[:], key[:keySize])

	// The nonce is of type [24]byte and part of the data we will receive
	nonce := new([nonceSize]byte)

	// Read the nonce from in, it is in the first 24 bytes
	copy(nonce[:], data[:nonceSize])

	// SimpleDecrypt the output of secretbox.Seal which contains the nonce and
	// the encrypted message
	message, ok := secretbox.Open(nil, data[nonceSize:], nonce, naclKey)
	if ok {
		return message, nil
	}
	return nil, errors.New("Decryption failed")
}

// RandomPadEncrypt generates a random pad and returns the encrypted data, the pad, and an error if any
func RandomPadEncrypt(key, message []byte) (pad, out []byte, err error) {
	pad = make([]byte, 32)
	_, err = rand.Read(pad)
	if err != nil {
		return
	}
	out, err = Encrypt(pad, key, message)
	return
}
