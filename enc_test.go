package goenc

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"fmt"

	"path/filepath"
	"runtime"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
	"github.com/kisom/testio"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/nacl/box"
)

var (
	testMessage = []byte("do not go gentle into that good night")
	testSecured []byte

	aliceSession, bobSession *Session
	ciphers                  []*Cipher
)

func init() {
	cbc, err := NewCipher(CBC, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	cfb, err := NewCipher(CFB, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	ctr, err := NewCipher(CTR, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	gcm, err := NewCipher(GCM, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	nacl, err := NewCipher(NaCL, testComplexity, []byte("this is a pad to use for our key mwahahaha 123456789"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	ciphers = []*Cipher{cbc, cfb, ctr, gcm, nacl}
}

func TestFileIO(t *testing.T) {

	Convey("We can successfully perform file writing and reading using the block cipher interface functions", t, func() {
		var tempDir = "/tmp"
		if runtime.GOOS == "windows" {
			userProfile := os.Getenv("USERPROFILE")
			tempDir = filepath.Join(userProfile, "AppData", "Local", "Temp")
		}

		bc, err := NewCipher(Mock, testComplexity)
		So(err, ShouldBeNil)
		d, err := ioutil.TempDir(tempDir, "")
		So(err, ShouldBeNil)
		defer os.RemoveAll(d)
		tf, err := ioutil.TempFile(d, "")
		So(err, ShouldBeNil)

		data := []byte("test data we'd like to 'encrypt' and save to file")
		key := []byte("test key which is meaningless")

		err = EncryptAndSave(bc, key, data, tf.Name())
		So(err, ShouldBeNil)

		err = tf.Close()
		So(err, ShouldBeNil)

		nd, err := ReadEncryptedFile(bc, key, tf.Name())
		So(err, ShouldBeNil)
		So(bytes.Equal(data, nd), ShouldBeTrue)
	})

}

func TestFileIOErrors(t *testing.T) {
	Convey("We can get errors on file io when we should", t, func() {
		c, err := NewCipher(GCM, testComplexity)
		So(err, ShouldBeNil)

		err = EncryptAndSave(c, []byte{}, []byte{}, "")
		So(err, ShouldNotBeNil)

		_, err = ReadEncryptedFile(c, []byte{}, "")
		So(err, ShouldNotBeNil)

		err = EncryptAndSaveWithPerms(c, []byte{}, []byte{}, "", 0644)
		So(err, ShouldNotBeNil)
	})
}

var (
	alicePub, alicePriv *[32]byte
	bobPub, bobPriv     *[32]byte
)

func TestGenerateKeys(t *testing.T) {
	var err error

	alicePub, alicePriv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bobPub, bobPriv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestDeriveKey(t *testing.T) {
	Convey("We can test a derived key in order to encrypt and decrypt text", t, func() {
		c, err := NewCipher(GCM, testComplexity)
		So(err, ShouldBeNil)

		salt, err := generate.RandBytes(SaltSize)
		So(err, ShouldBeNil)

		key, err := DeriveKey([]byte("password"), salt, c.DerivedKeyN, c.BlockCipher.KeySize())
		So(err, ShouldBeNil)
		plaintext := []byte("This is some data")
		data, err := c.BlockCipher.Encrypt(key, plaintext)
		So(err, ShouldBeNil)

		key2, err := DeriveKey([]byte("password"), salt, c.DerivedKeyN, c.BlockCipher.KeySize())
		So(err, ShouldBeNil)

		data, err = c.BlockCipher.Decrypt(key2, data)
		So(err, ShouldBeNil)
		So(bytes.Equal(plaintext, data), ShouldBeTrue)
	})
}

func TestDeriveKeyErrors(t *testing.T) {
	Convey("We can get derived key errors when we should", t, func() {

		_, err := DeriveKey([]byte{}, []byte{}, 0, 0)
		So(err, ShouldNotBeNil)
	})
}

func TestSessionSetup(t *testing.T) {

	Convey("We can test all ciphers with a session", t, func() {
		for _, c := range ciphers {

			pub, priv, err := GenerateKeyPair()
			So(err, ShouldBeNil)

			conn := testio.NewBufferConn()
			conn.WritePeer(pub[:])

			aliceSession, err = Dial(conn, c)
			So(err, ShouldBeNil)

			var peer [64]byte
			_, err = conn.ReadClient(peer[:])
			So(err, ShouldBeNil)

			bobSession = &Session{
				recvKey: new([32]byte),
				sendKey: new([32]byte),
				Channel: testio.NewBufCloser(nil),
				Cipher:  c,
			}

			bobSession.KeyExchange(priv, &peer, false)
			aliceSession.Channel = bobSession.Channel
			err = aliceSession.Send(testMessage)
			So(err, ShouldBeNil)

			out, err := bobSession.Receive()
			So(err, ShouldBeNil)

			if !bytes.Equal(out, testMessage) {
				t.Fatal("recovered message doesn't match original")
			}

			if err = aliceSession.Send(nil); err == nil {
				t.Fatal("empty message should trigger an error")
			}

			aliceSession.Close()
			bobSession.Close()
		}
	})

}

var oldMessage []byte

func TestSessionListen(t *testing.T) {

	Convey("We can test session listening with all ciphers", t, func() {

		for _, c := range ciphers {
			pub, priv, err := GenerateKeyPair()
			So(err, ShouldBeNil)

			conn := testio.NewBufferConn()
			conn.WritePeer(pub[:])

			aliceSession, err = Listen(conn, c)
			So(err, ShouldBeNil)

			var peer [64]byte
			_, err = conn.ReadClient(peer[:])
			So(err, ShouldBeNil)

			bobSession = &Session{
				recvKey: new([32]byte),
				sendKey: new([32]byte),
				Channel: testio.NewBufCloser(nil),
				Cipher:  c,
			}

			bobSession.KeyExchange(priv, &peer, true)

			aliceSession.Channel = bobSession.Channel
			err = aliceSession.Send(testMessage)
			So(err, ShouldBeNil)

			out, err := bobSession.Receive()
			So(err, ShouldBeNil)

			So(bobSession.LastRecv(), ShouldBeGreaterThan, 0)
			So(aliceSession.LastSent(), ShouldBeGreaterThan, 0)
			// The NBA is always listening, on and off the court.
			oldMessage = out

			if !bytes.Equal(out, testMessage) {
				t.Fatal("recovered message doesn't match original")
			}

			for i := 0; i < 4; i++ {
				randMessage, err := generate.RandBytes(128)
				So(err, ShouldBeNil)

				err = aliceSession.Send(randMessage)
				So(err, ShouldBeNil)

				out, err = bobSession.Receive()
				So(err, ShouldBeNil)

				if !bytes.Equal(out, randMessage) {
					t.Fatal("recovered message doesn't match original")
				}
			}

			// NBA injects an old message into the channel. Damn those hoops!
			bobSession.Channel.Write(oldMessage)
			_, err = bobSession.Receive()
			So(err, ShouldNotBeNil)
		}
	})

}

func TestErrors(t *testing.T) {
	Convey("We can get appropriate errors", t, func() {
		_, err := NewCipher(NaCL, testComplexity)
		So(err, ShouldEqual, encerrors.ErrNoPadProvided)

		_, err = NewCipher(50, testComplexity)
		So(err, ShouldEqual, encerrors.ErrInvalidCipherKind)

		_, err = UnmarshalMessage([]byte{})
		So(err, ShouldEqual, encerrors.ErrInvalidMessageLength)

		c, err := NewCipher(GCM, testComplexity)
		So(err, ShouldBeNil)
		s := NewSession(testio.NewBufCloser(nil), c)

		_, err = s.Decrypt([]byte{})
		So(err, ShouldNotBeNil)

		msg := []byte("this is a message")
		k, err := generate.Key()
		So(err, ShouldBeNil)
		s.sendKey = k
		s.recvKey = k
		data, err := s.Encrypt(msg)
		So(err, ShouldBeNil)
		s.lastRecv = 40
		_, err = s.Decrypt(data)
		So(err, ShouldNotBeNil)

		_, err = DeriveKey([]byte{}, []byte{}, 0, 1)
		So(err, ShouldNotBeNil)
	})
}
