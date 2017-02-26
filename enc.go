// package goenc contains functions for working with encryption
// work is derived from many sources:
//
// http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key
// https://golang.org/pkg/crypto/cipher/
// https://leanpub.com/gocrypto/read#leanpub-auto-aes-cbc
// https://github.com/hashicorp/memberlist/blob/master/security.go
package goenc

import (
	"encoding/binary"
	"io"

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
	TODO(cmc): Verify this isn't horrifically insecure and have this reviewed by an expert before publishing
*/

type BlockCipher interface {
	Encrypt(key, plaintext []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
	KeySize() int
}

func BCEncryptAndSaveWithPerms(cipher BlockCipher, key, plaintext []byte, path string, perm os.FileMode) error {
	data, err := cipher.Encrypt(key, plaintext)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, perm)
}

func BCEncryptAndSave(cipher BlockCipher, key, plaintext []byte, path string) error {
	return BCEncryptAndSaveWithPerms(cipher, key, plaintext, path, 0644)
}

func BCReadEncryptedFile(cipher BlockCipher, key []byte, path string) ([]byte, error) {
	ciphertext, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.Decrypt(key, ciphertext)
	return plaintext, err
}

type CipherKind int

const (
	GCM CipherKind = iota
	NaCL
	CFB
	CBC
	CTR
	Mock
)

const (
	SaltSize = 64
)

type Cipher struct {
	BlockCipher
	DerivedKeyN int
}

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

func (c *Cipher) Encrypt(password, plaintext []byte) ([]byte, error) {
	salt, err := generate.RandBytes(SaltSize)
	if err != nil {
		return nil, err
	}

	key, err := DeriveKey(password, salt, c.DerivedKeyN, c.BlockCipher.KeySize())
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

const Overhead = SaltSize + secretbox.Overhead + generate.NonceSize

func (c *Cipher) Decrypt(password, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, encerrors.ErrInvalidMessageLength
	}

	key, err := DeriveKey(password, ciphertext[:SaltSize], c.DerivedKeyN, c.KeySize())
	if err != nil {
		return nil, err
	}

	out, err := c.BlockCipher.Decrypt(key, ciphertext[SaltSize:])
	Zero(key) // Zero key immediately after
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

func (m *MockBlockCipher) KeySize() int {
	return 32
}

type StreamCipher interface {
	// EncryptStream encrypts bytes into w from r
	EncryptStream(key []byte, w io.Writer, r io.Reader) error
	// DecryptStream decrypts bytes into w from r
	DecryptStream(key []byte, w io.Writer, r io.Reader) error
}

type Message struct {
	Number   uint32
	Contents []byte
}

func NewMessage(in []byte, num uint32) *Message {
	return &Message{Contents: in, Number: num}
}

func (m *Message) Marshal() []byte {
	out := make([]byte, 4, len(m.Contents)+4)
	binary.BigEndian.PutUint32(out[:4], m.Number)
	return append(out, m.Contents...)
}

func UnmarshalMessage(in []byte) (*Message, error) {
	m := &Message{}
	if len(in) <= 4 {
		return m, encerrors.ErrInvalidMessageLength
	}

	m.Number = binary.BigEndian.Uint32(in[:4])
	m.Contents = in[4:]
	return m, nil
}

type Channel io.ReadWriter

type Session struct {
	Cipher   BlockCipher
	Channel  Channel
	lastSent uint32
	lastRecv uint32
	sendKey  []byte
	recvKey  []byte
}

func NewSession(ch Channel, c BlockCipher) *Session {
	return &Session{Cipher: c, Channel: ch}
}

func (s *Session) LastSent() uint32 {
	return s.lastSent
}

func (s *Session) LastRecv() uint32 {
	return s.lastRecv
}

func (s *Session) Encrypt(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, encerrors.ErrInvalidMessageLength
	}

	s.lastSent++
	m := NewMessage(message, s.lastSent)
	return s.Cipher.Encrypt(s.sendKey, m.Marshal())
}

func (s *Session) Decrypt(message []byte) ([]byte, error) {
	out, err := s.Cipher.Decrypt(s.recvKey, message)
	if err != nil {
		return nil, err
	}

	m, err := UnmarshalMessage(out)
	if err != nil {
		return nil, err
	}

	// if this number is less than or equal to the last received message, this is a replay and we bail
	if m.Number <= s.lastRecv {
		return nil, encerrors.ErrInvalidMessageID
	}

	s.lastRecv = m.Number

	return m.Contents, nil
}

const (
	InteractiveComplexity = 1 << (iota + 14)
	Complexity15
	Complexity16
	Complexity17
	Complexity18
	Complexity19
	AgressiveComplexity
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

func Zero(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}
