package nacl

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/alistanis/goenc/generate"
	. "github.com/smartystreets/goconvey/convey"
)

func TestEncryptDecrypt(t *testing.T) {
	Convey("We can test encrypting and decrypting bytes using secretbox (NaCL)", t, func() {
		pad := make([]byte, 32)
		_, err := rand.Read(pad)
		So(err, ShouldBeNil)

		b := []byte("This is a message we'd like to encrypt")
		k := []byte("super weak key")

		out, err := Encrypt(pad, k, b)
		So(err, ShouldBeNil)
		So(bytes.Equal(b, out), ShouldBeFalse)

		msg, err := Decrypt(pad, k, out)
		So(err, ShouldBeNil)

		So(bytes.Equal(b, msg), ShouldBeTrue)

		pad, out, err = RandomPadEncrypt(k, b)
		So(bytes.Equal(b, out), ShouldBeFalse)
		msg, err = Decrypt(pad, k, out)
		So(err, ShouldBeNil)
		So(bytes.Equal(b, msg), ShouldBeTrue)
	})
}

func TestCipher_Encrypt(t *testing.T) {
	Convey("We can test encrypting and decrypting with the Cipher struct", t, func() {

		pad := make([]byte, 32)
		_, err := rand.Read(pad)
		So(err, ShouldBeNil)
		c := &Cipher{Pad: pad}
		So(c.KeySize(), ShouldEqual, 32)
		b := []byte("This is a message we'd like to encrypt")
		k := []byte("super weak key")

		out, err := c.Encrypt(k, b)
		So(err, ShouldBeNil)
		So(bytes.Equal(b, out), ShouldBeFalse)

		msg, err := c.Decrypt(k, out)
		So(err, ShouldBeNil)

		So(bytes.Equal(b, msg), ShouldBeTrue)

		pad, out, err = RandomPadEncrypt(k, b)
		So(bytes.Equal(b, out), ShouldBeFalse)
		msg, err = Decrypt(pad, k, out)
		So(err, ShouldBeNil)
		So(bytes.Equal(b, msg), ShouldBeTrue)
	})
}

func TestErrors(t *testing.T) {
	Convey("We can get the appropriate errors", t, func() {
		pad := []byte{}
		_, err := Encrypt(pad, nil, nil)
		So(err, ShouldNotBeNil)

		b := []byte("This is a message we'd like to encrypt")
		k := []byte("super weak key")

		pad, err = generate.RandBytes(32)
		So(err, ShouldBeNil)
		data, err := Encrypt(pad, k, b)
		So(err, ShouldBeNil)

		_, err = Decrypt(pad, []byte("Bad key"), data)
		So(err.Error(), ShouldEqual, "Decryption failed")

	})
}
