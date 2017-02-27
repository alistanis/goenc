package cfb

import (
	"math/rand"
	"testing"

	"bytes"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
	. "github.com/smartystreets/goconvey/convey"
)

func TestEncryptDecrypt(t *testing.T) {
	Convey("We can test encrypting and decrpyting bytes and strings", t, func() {
		s := "this is a test string to encrypt"
		key := make([]byte, 32)
		_, err := rand.Read(key)
		So(err, ShouldBeNil)

		es, err := EncryptString(string(key), s)
		So(err, ShouldBeNil)
		So(s, ShouldNotEqual, es)

		ds, err := DecryptString(string(key), es)
		So(err, ShouldBeNil)
		So(ds, ShouldEqual, s)
	})

}

var (
	text = "this is some text to encrypt"
)

func TestEncrypt(t *testing.T) {
	Convey("We can encrypt and decrypt messages using a key", t, func() {
		k, err := generate.Key()
		So(err, ShouldBeNil)
		key := k[:]
		data, err := Encrypt(key, []byte(text))
		So(err, ShouldBeNil)
		So(bytes.Equal([]byte(text), data), ShouldBeFalse)

		data, err = Decrypt(key, data)
		So(err, ShouldBeNil)
		So(bytes.Equal([]byte(text), data), ShouldBeTrue)
	})
}

func TestCipher_Encrypt(t *testing.T) {
	Convey("We can encrypt and decrypt with the cipher struct", t, func() {
		c := New()
		So(c.KeySize(), ShouldEqual, KeySize)
		k, err := generate.Key()
		So(err, ShouldBeNil)
		key := k[:]
		data, err := c.Encrypt(key, []byte(text))
		So(bytes.Equal([]byte(text), data), ShouldBeFalse)

		data, err = c.Decrypt(key, data)
		So(err, ShouldBeNil)
		So(bytes.Equal([]byte(text), data), ShouldBeTrue)
	})
}

func TestErrors(t *testing.T) {
	Convey("We can get the appropriate errors", t, func() {
		key, err := generate.RandBytes(30)
		So(err, ShouldBeNil)
		_, err = Encrypt(key, []byte{})
		errText := "crypto/aes: invalid key size 30"
		So(err.Error(), ShouldEqual, errText)
		_, err = Decrypt(key, []byte{})
		So(err.Error(), ShouldEqual, errText)

		k, err := generate.Key()
		So(err, ShouldBeNil)
		key = k[:]

		_, err = Decrypt(key, []byte{})
		So(err, ShouldEqual, encerrors.ErrInvalidMessageLength)

	})
}
