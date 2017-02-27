package ctr

import (
	"bytes"
	"testing"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	text = "this is some text to encrypt"
)

func TestEncrypt(t *testing.T) {
	Convey("We can encrypt and decrypt messages using a key", t, func() {
		k, err := Key()
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
	Convey("We can encrypt and decrypt messages using a cipher struct", t, func() {
		c := New()
		So(c.KeySize(), ShouldEqual, KeySize)
		k, err := Key()
		So(err, ShouldBeNil)
		key := k[:]
		data, err := c.Encrypt(key, []byte(text))
		So(err, ShouldBeNil)
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
		So(err, ShouldEqual, encerrors.ErrInvalidKeyLength)
		_, err = Decrypt(key, []byte{})
		So(err, ShouldEqual, encerrors.ErrInvalidKeyLength)

		k, err := generate.Key()
		So(err, ShouldBeNil)
		key = k[:]

		_, err = Decrypt(key, []byte{})
		So(err, ShouldEqual, encerrors.ErrInvalidKeyLength)
		k2, err := Key()
		So(err, ShouldBeNil)
		key = k2[:]
		_, err = Decrypt(key, []byte{})
		So(err, ShouldEqual, encerrors.ErrInvalidMessageLength)
		data, err := generate.RandBytes(NonceSize + MACSize)
		So(err, ShouldBeNil)
		_, err = Decrypt(key, data)
		So(err, ShouldEqual, encerrors.ErrInvalidMessageLength)

		data, err = generate.RandBytes(NonceSize + MACSize + 1)
		So(err, ShouldBeNil)
		_, err = Decrypt(key, data)
		So(err, ShouldEqual, encerrors.ErrInvalidSum)
	})
}
