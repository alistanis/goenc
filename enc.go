// Package goenc contains functions for working with encryption
package goenc

// work is derived from many sources:
//
// http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key
// https://golang.org/pkg/crypto/cipher/
// https://leanpub.com/gocrypto/read#leanpub-auto-aes-cbc
// https://github.com/hashicorp/memberlist/blob/master/security.go

import (
	"encoding/binary"

	"io/ioutil"

	"os"

	"github.com/alistanis/goenc/aes/cbc"
	"github.com/alistanis/goenc/aes/cfb"
	"github.com/alistanis/goenc/aes/ctr"
	"github.com/alistanis/goenc/aes/gcm"
	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
	"github.com/alistanis/goenc/nacl"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

/*
	TODO(cmc): Verify this isn't horrifically insecure and have this reviewed by a(n) expert(s) before publishing
*/

// BlockCipher represents a cipher that encodes and decodes chunks of data at a time
type BlockCipher interface {
	Encrypt(key, plaintext []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
	KeySize() int
}

//---------------------------------------------------------------------------
// BlockCipherInterface Functions - these should not be used with large files
//--------------------------------------------------------------------------------

// EncryptAndSaveWithPerms encrypts data and saves it to a file with the given permissions using the given key
func EncryptAndSaveWithPerms(cipher BlockCipher, key, plaintext []byte, path string, perm os.FileMode) error {
	data, err := cipher.Encrypt(key, plaintext)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, perm)
}

// EncryptAndSave encrypts data and saves it to a file with the permissions 0644
func EncryptAndSave(cipher BlockCipher, key, plaintext []byte, path string) error {
	return EncryptAndSaveWithPerms(cipher, key, plaintext, path, 0644)
}

// ReadEncryptedFile reads a file a path and attempts to decrypt the data there with the given key
func ReadEncryptedFile(cipher BlockCipher, key []byte, path string) ([]byte, error) {
	ciphertext, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.Decrypt(key, ciphertext)
	return plaintext, err
}

// CipherKind represents what kind of cipher to use
type CipherKind int

// CipherKind constants
const (
	CBC CipherKind = iota
	CFB
	CTR
	GCM
	NaCL

	Mock
)

const (
	// SaltSize sets a generic salt size
	SaltSize = 64
)

// Cipher is a struct that contains a BlockCipher interface and stores a DerivedKey Complexity number
type Cipher struct {
	BlockCipher
	DerivedKeyN int
}

func (c *Cipher) DeriveKey(pass, salt []byte) ([]byte, error) {
	return DeriveKey(pass, salt, c.DerivedKeyN, c.KeySize())
}

// NewCipher returns a new Cipher containing a BlockCipher interface based on the CipherKind
func NewCipher(kind CipherKind, derivedKeyN int, args ...[]byte) (*Cipher, error) {
	c := &Cipher{DerivedKeyN: derivedKeyN}
	switch kind {
	case GCM:
		c.BlockCipher = gcm.New()
	case NaCL:
		// special case, we need to define a pad for nacl
		if len(args) == 0 {
			return nil, encerrors.ErrNoPadProvided
		}
		n := &nacl.Cipher{}
		n.Pad = args[0]
		c.BlockCipher = n
	case CFB:
		c.BlockCipher = cfb.New()
	case CBC:
		c.BlockCipher = cbc.New()
	case CTR:
		c.BlockCipher = ctr.New()
	case Mock:
		c.BlockCipher = &MockBlockCipher{}
	default:
		return nil, encerrors.ErrInvalidCipherKind
	}
	return c, nil
}

// EncryptWithPassword takes a password, plaintext, and derives a key based on that password,
// then encrypting that data with the underlying block cipher and appending the salt to the output
func (c *Cipher) EncryptWithPassword(password, plaintext []byte) ([]byte, error) {
	salt, err := generate.RandBytes(SaltSize)
	if err != nil {
		return nil, err
	}

	key, err := c.DeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	out, err := c.BlockCipher.Encrypt(key, plaintext)
	Zero(key)
	if err != nil {
		return nil, err
	}

	out = append(salt, out...)
	return out, nil
}

// Overhead is the amount of Overhead contained in the ciphertext
const Overhead = SaltSize + secretbox.Overhead + generate.NonceSize

// Decrypt takes a password and ciphertext, derives a key, and attempts to decrypt that data
func (c *Cipher) DecryptWithPassword(password, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, encerrors.ErrInvalidMessageLength
	}

	key, err := c.DeriveKey(password, ciphertext[:SaltSize])
	if err != nil {
		return nil, err
	}

	out, err := c.BlockCipher.Decrypt(key, ciphertext[SaltSize:])
	Zero(key)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// MockBlockCipher implements BlockCipher but does nothing
type MockBlockCipher struct{}

// Encrypt in this case is only implementing the BlockCipher interface, it doesn't do anything
func (m *MockBlockCipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

// Decrypt in this case is only implementing the BlockCipher interface, it doesn't do anything
func (m *MockBlockCipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

// KeySize is a mock key size to use with the mock cipher
func (m *MockBlockCipher) KeySize() int {
	return 32
}

// Message represents a message being passed, and contains its contents and a sequence number
type Message struct {
	Number   uint32
	Contents []byte
}

// NewMessage returns a new message
func NewMessage(in []byte, num uint32) *Message {
	return &Message{Contents: in, Number: num}
}

// Marshal encodes a sequence number into the data that we wish to send
func (m *Message) Marshal() []byte {
	out := make([]byte, 4, len(m.Contents)+4)
	binary.BigEndian.PutUint32(out[:4], m.Number)
	return append(out, m.Contents...)
}

// UnmarshalMessage decodes bytes into a message pointer
func UnmarshalMessage(in []byte) (*Message, error) {
	if len(in) <= 4 {
		return nil, encerrors.ErrInvalidMessageLength
	}
	m := &Message{}
	m.Number = binary.BigEndian.Uint32(in[:4])
	m.Contents = in[4:]
	return m, nil
}

const (
	// testComplexity is unexported because we don't want to use such a weak key in the wild
	testComplexity = 1 << (iota + 7)
)

const (
	// N Complexity in powers of 2 for key Derivation

	// InteractiveComplexity - recommended complexity for interactive sessions
	InteractiveComplexity = 1 << (iota + 14)
	// Complexity15 is 2^15
	Complexity15
	// Complexity16 is 2^16
	Complexity16
	// Complexity17 is 2^17
	Complexity17
	// Complexity18 is 2^18
	Complexity18
	// Complexity19 is 2^19
	Complexity19
	// AggressiveComplexity is 2^20 (don't use this unless you have incredibly strong CPU power
	AggressiveComplexity
)

// DeriveKey generates a new NaCl key from a passphrase and salt.
// This is a costly operation.
func DeriveKey(pass, salt []byte, N, keySize int) ([]byte, error) {
	var naclKey = make([]byte, keySize)
	key, err := scrypt.Key(pass, salt, N, 8, 1, keySize)
	if err != nil {
		return nil, err
	}

	copy(naclKey, key)
	Zero(key)
	return naclKey, nil
}

// Zero zeroes out bytes of data so that it does not stay in memory any longer than necessary
func Zero(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}
