package goenc

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"fmt"

	"github.com/alistanis/goenc/generate"
	"github.com/kisom/testio"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/nacl/box"
)

func TestBCFileIO(t *testing.T) {

	Convey("We can succesfully perform file writing and reading using the block cipher interface functions", t, func() {
		bc, err := NewCipher(Mock, 16384)
		So(err, ShouldBeNil)
		d, err := ioutil.TempDir("/tmp", "")
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

var (
	testMessage = []byte("do not go gentle into that good night")
	testSecured []byte

	aliceSession, bobSession *Session
	ciphers                  []*Cipher
)

func init() {
	gcm, err := NewCipher(GCM, InteractiveComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	cbc, err := NewCipher(CBC, InteractiveComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	ctr, err := NewCipher(CTR, InteractiveComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	nacl, err := NewCipher(NaCL, InteractiveComplexity, []byte("this is a pad to use for our key mwahahaha 123456789"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	ciphers = []*Cipher{gcm, cbc, ctr, nacl}
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
