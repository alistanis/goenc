package generate

import (
	"crypto/rand"
	"io"
)

const (
	// KeySize is the default key size for most types of encryption
	KeySize = 32
	// NonceSize is the default NonceSize
	NonceSize = 24
)

// Key creates a new random secret key.
func Key() (*[KeySize]byte, error) {
	key := new([KeySize]byte)
	_, err := io.ReadFull(rand.Reader, key[:])
	return key, err
}

// Nonce creates a new random nonce.
func Nonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

// RandBytes returns a slice of random bytes of the size given
func RandBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, buf)
	return buf, err
}

// RandString returns a random string with the given length
func RandString(length int) (string, error) {
	b, err := RandBytes(length)
	return string(b), err
}
