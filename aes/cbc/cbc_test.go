package cbc

import (
	"bytes"
	"testing"

	"crypto/aes"

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
	Convey("We can encrypt using the Cipher struct", t, func() {
		c := New()
		So(c.KeySize(), ShouldEqual, 64)
		k, err := Key()
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
	Convey("We can get the appropriate errors when failing certain conditions", t, func() {
		Convey("Unpad:", func() {
			b := unpad([]byte{})
			So(b, ShouldBeNil)

			b, err := generate.RandBytes(17)
			So(err, ShouldBeNil)
			b = unpad(b)
			So(b, ShouldBeNil)

			b, err = generate.RandBytes(16)
			So(err, ShouldBeNil)
			b = unpad(b)
			So(b, ShouldBeNil)

			b = []byte{0}
			b = unpad(b)
			So(b, ShouldBeNil)
		})

		Convey("Encrypt:", func() {
			k, err := generate.RandBytes(40)
			So(err, ShouldBeNil)
			_, err = Encrypt(k, []byte{})
			So(err, ShouldEqual, encerrors.ErrInvalidKeyLength)
		})

		Convey("Decrypt:", func() {
			k, err := generate.RandBytes(40)
			So(err, ShouldBeNil)
			_, err = Decrypt(k, []byte{})
			So(err, ShouldEqual, encerrors.ErrInvalidKeyLength)
			ciphertext, err := generate.RandBytes(aes.BlockSize + 1)
			So(err, ShouldBeNil)
			k, err = generate.RandBytes(KeySize)
			So(err, ShouldBeNil)
			_, err = Decrypt(k, ciphertext)
			So(err, ShouldEqual, encerrors.ErrInvalidMessageLength)

			ciphertext, err = generate.RandBytes(aes.BlockSize)
			So(err, ShouldBeNil)
			_, err = Decrypt(k, ciphertext)
			So(err, ShouldEqual, encerrors.ErrInvalidMessageLength)

			ciphertext, err = generate.RandBytes(aes.BlockSize * 4)
			So(err, ShouldBeNil)
			_, err = Decrypt(k, ciphertext)
			So(err, ShouldEqual, encerrors.ErrInvalidSum)
		})
	})
}
