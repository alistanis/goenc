package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
)

const NonceSize = generate.NonceSize
const KeySize = generate.KeySize

type Cipher struct {
}

func New() *Cipher {
	return &Cipher{}
}

func (c *Cipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	return Encrypt(key, plaintext)
}

func (c *Cipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	return Decrypt(key, ciphertext)
}

func (c *Cipher) KeySize() int {
	return KeySize
}

// Encrypt secures a message using AES-GCM.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, NonceSize)
	if err != nil {
		return nil, err
	}

	nonce, err := generate.Nonce()
	if err != nil {
		return nil, err
	}

	// Seal will append the output to the first argument; the usage
	// here appends the ciphertext to the nonce. The final parameter
	// is any additional data to be authenticated.
	out := gcm.Seal(nonce[:], nonce[:], plaintext, nil)
	return out, nil
}

// EncryptString
func EncryptString(key, plaintext string) (string, error) {
	data, err := Encrypt([]byte(key), []byte(plaintext))
	return string(data), err
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	copy(nonce, ciphertext)
	return gcm.Open(nil, nonce[:], ciphertext[NonceSize:], nil)
}

func DecryptString(key, ciphertext string) (string, error) {
	data, err := Decrypt([]byte(key), []byte(ciphertext))
	return string(data), err
}

// EncryptWithID secures a message and prepends a 4-byte sender ID
// to the message. The end bit is tricky, because gcm.Seal modifies buf, and this is necessary
func EncryptWithID(key, message []byte, sender uint32) ([]byte, error) {
	buf := make([]byte, 4)

	binary.BigEndian.PutUint32(buf, sender)

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, NonceSize)
	if err != nil {
		return nil, err
	}

	nonce, err := generate.Nonce()
	if err != nil {
		return nil, err
	}

	buf = append(buf, nonce[:]...)
	return gcm.Seal(buf, nonce[:], message, buf[:4]), nil
}

// EncryptStringWithID is a helper function to work with strings instead of bytes
func EncryptStringWithID(key, message string, sender uint32) (string, error) {
	data, err := EncryptWithID([]byte(key), []byte(message), sender)
	return string(data), err
}

// DecryptWithID takes an encrypted message and a KeyForID function (to get a key from a cache or a database perhaps)
// It checks the first 4 bytes for prepended header data, in this case, a sender ID
func DecryptWithID(message []byte, k KeyRetriever) ([]byte, error) {

	if len(message) <= NonceSize+4 {
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

	gcm, err := cipher.NewGCMWithNonceSize(c, NonceSize)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	copy(nonce, message[4:])

	ciphertext := message[4+NonceSize:]

	// Decrypt the message, using the sender ID as the additional
	// data requiring authentication.
	out, err := gcm.Open(nil, nonce, ciphertext, message[:4])
	if err != nil {
		return nil, err
	}

	return out, nil
}

// DecryptStringWithID is a helper function to work with strings instead of bytes
func DecryptStringWithID(message string, k KeyRetriever) (string, error) {
	data, err := DecryptWithID([]byte(message), k)
	return string(data), err
}

type KeyRetriever interface {
	KeyForID(uint32) ([]byte, error)
}

// Helper is designed to make it easy to call EncryptWithID and DecryptWithID by assigning the KeyForIDFunc
// it implements KeyRetriever and provides convenience functions
// It also serves as an example for how to use KeyRetriever
type Helper struct {
	KeyForIDFunc func(uint32) ([]byte, error)
}

// NewHelper returns a new helper
func NewHelper(f func(uint32) ([]byte, error)) *Helper {
	return &Helper{f}
}

func (h *Helper) KeyForID(u uint32) ([]byte, error) {
	return h.KeyForIDFunc(u)
}

func (h *Helper) EncryptWithID(key, message []byte, sender uint32) ([]byte, error) {
	return EncryptWithID(key, message, sender)
}

func (h *Helper) DecryptWithID(message []byte) ([]byte, error) {
	return DecryptWithID(message, h)
}

func (h *Helper) EncryptStringWithID(key, message string, sender uint32) (string, error) {
	return EncryptStringWithID(key, message, sender)
}

func (h *Helper) DecryptStringWithID(message string) (string, error) {
	return DecryptStringWithID(message, h)
}
