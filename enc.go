// Package goenc contains functions for working with encryption
package goenc

// work is derived from many sources:
//
// http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key
// https://golang.org/pkg/crypto/cipher/
// https://leanpub.com/gocrypto/read#leanpub-auto-aes-cbc
// https://github.com/hashicorp/memberlist/blob/master/security.go

import (
	"crypto/rand"
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
	"golang.org/x/crypto/nacl/box"
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

// Encrypt takes a password, plaintext, and derives a key based on that password,
// then encrypting that data with the underlying block cipher
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

// Overhead is the amount of Overhead contained in the ciphertext
const Overhead = SaltSize + secretbox.Overhead + generate.NonceSize

// Decrypt takes a password and ciphertext, derives a key, and attempts to decrypt that data
func (c *Cipher) Decrypt(password, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, encerrors.ErrInvalidMessageLength
	}

	key, err := DeriveKey(password, ciphertext[:SaltSize], c.DerivedKeyN, c.KeySize())
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
	m := &Message{}
	if len(in) <= 4 {
		return m, encerrors.ErrInvalidMessageLength
	}

	m.Number = binary.BigEndian.Uint32(in[:4])
	m.Contents = in[4:]
	return m, nil
}

// Channel is a typed io.ReadWriter used for communicating securely
type Channel io.ReadWriter

// Session represents a session that can be used to pass messages over a secure channel
type Session struct {
	Cipher *Cipher
	Channel
	lastSent uint32
	lastRecv uint32
	sendKey  *[32]byte
	recvKey  *[32]byte
}

// LastSent returns the last sent message id
func (s *Session) LastSent() uint32 {
	return s.lastSent
}

// LastRecv returns the last received message id
func (s *Session) LastRecv() uint32 {
	return s.lastRecv
}

// Encrypt encrypts a message with an embedded message id
func (s *Session) Encrypt(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, encerrors.ErrInvalidMessageLength
	}

	s.lastSent++
	m := NewMessage(message, s.lastSent)
	return s.Cipher.Encrypt(s.sendKey[:], m.Marshal())
}

// Decrypt decrypts a message and checks that its message id is valid
func (s *Session) Decrypt(message []byte) ([]byte, error) {
	out, err := s.Cipher.Decrypt(s.recvKey[:], message)
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

// Send encrypts the message and sends it out over the channel.
func (s *Session) Send(message []byte) error {
	m, err := s.Encrypt(message)
	if err != nil {
		return err
	}

	err = binary.Write(s.Channel, binary.BigEndian, uint32(len(m)))
	if err != nil {
		return err
	}

	_, err = s.Channel.Write(m)
	return err
}

// Receive listens for a new message on the channel.
func (s *Session) Receive() ([]byte, error) {
	var mlen uint32
	err := binary.Read(s.Channel, binary.BigEndian, &mlen)
	if err != nil {
		return nil, err
	}

	message := make([]byte, int(mlen))
	_, err = io.ReadFull(s.Channel, message)
	if err != nil {
		return nil, err
	}

	return s.Decrypt(message)
}

// GenerateKeyPair generates a new key pair. This can be used to get a
// new key pair for setting up a rekeying operation during the session.
func GenerateKeyPair() (pub *[64]byte, priv *[64]byte, err error) {
	pub = new([64]byte)
	priv = new([64]byte)

	recvPub, recvPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	copy(pub[:], recvPub[:])
	copy(priv[:], recvPriv[:])

	sendPub, sendPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	copy(pub[32:], sendPub[:])
	copy(priv[32:], sendPriv[:])
	return pub, priv, err
}

// Close zeroises the keys in the session. Once a session is closed,
// the traffic that was sent over the channel can no longer be decrypted
// and any attempts at sending or receiving messages over the channel
// will fail.
func (s *Session) Close() error {
	Zero(s.sendKey[:])
	Zero(s.recvKey[:])
	return nil
}

// keyExchange is a convenience function that takes keys as byte slices,
// copying them into the appropriate arrays.
func keyExchange(shared *[32]byte, priv, pub []byte) {
	// Copy the private key and wipe it, as it will no longer be needed.
	var kexPriv [32]byte
	copy(kexPriv[:], priv)
	Zero(priv)

	var kexPub [32]byte
	copy(kexPub[:], pub)

	box.Precompute(shared, &kexPub, &kexPriv)
	Zero(kexPriv[:])
}

// NewSession returns a new *Session
func NewSession(ch Channel, c *Cipher) *Session {
	return &Session{
		Cipher:  c,
		Channel: ch,
		recvKey: new([32]byte),
		sendKey: new([32]byte),
	}
}

// Dial sets up a new session over the channel by generating a new pair
// of Curve25519 keypairs, sending its public keys to the peer, and
// reading the peer's public keys back.
func Dial(ch Channel, c *Cipher) (*Session, error) {
	var peer [64]byte
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	_, err = ch.Write(pub[:])
	if err != nil {
		return nil, err
	}

	// Make sure the entire public key is read.
	_, err = io.ReadFull(ch, peer[:])
	if err != nil {
		return nil, err
	}

	s := NewSession(ch, c)

	s.KeyExchange(priv, &peer, true)
	return s, nil
}

// Listen waits for a peer to Dial in, then sets up a key exchange
// and session.
func Listen(ch Channel, c *Cipher) (*Session, error) {
	var peer [64]byte
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Ensure the entire peer key is read.
	_, err = io.ReadFull(ch, peer[:])
	if err != nil {
		return nil, err
	}

	_, err = ch.Write(pub[:])
	if err != nil {
		return nil, err
	}

	s := NewSession(ch, c)

	s.KeyExchange(priv, &peer, false)
	return s, nil
}

// KeyExchange - Rekey is used to perform the key exchange once both sides have
// exchanged their public keys. The underlying message protocol will
// need to actually initiate and carry out the key exchange, and call
// this once that is finished. The private key will be zeroised after
// calling this function. If the session is on the side that initiated
// the key exchange (e.g. by calling Dial), it should set the dialer
// argument to true. This will also reset the message counters for the
// session, as it will cause the session to use a new key.
func (s *Session) KeyExchange(priv, peer *[64]byte, dialer bool) {
	// This function denotes the dialer, who initiates the session,
	// as A. The listener is denoted as B. A is started using Dial,
	// and B is started using Listen.
	if dialer {
		// The first 32 bytes are the A->B link, where A is the
		// dialer. This key material should be used to set up the
		// A send key.
		keyExchange(s.sendKey, priv[:32], peer[:32])

		// The last 32 bytes are the B->A link, where A is the
		// dialer. This key material should be used to set up the A
		// receive key.
		keyExchange(s.recvKey, priv[32:], peer[32:])
	} else {
		// The first 32 bytes are the A->B link, where A is the
		// dialer. This key material should be used to set up the
		// B receive key.
		keyExchange(s.recvKey, priv[:32], peer[:32])

		// The last 32 bytes are the B->A link, where A is the
		// dialer. This key material should be used to set up the
		// B send key.
		keyExchange(s.sendKey, priv[32:], peer[32:])
	}
	s.lastSent = 0
	s.lastRecv = 0
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
	// Complexity19 is 2^18
	Complexity19
	// AggressiveComplexity is 2^19 (don't use this unless you have relatively strong CPU power
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
