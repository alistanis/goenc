package gcm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/alistanis/goenc/generate"
	. "github.com/smartystreets/goconvey/convey"
)

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
		So(bytes.Equal([]byte(text), data), ShouldBeTrue)

		s, err := EncryptString(string(key), text)
		So(err, ShouldBeNil)
		So(s, ShouldNotEqual, text)

		s, err = DecryptString(string(key), s)
		So(err, ShouldBeNil)
		So(s, ShouldEqual, text)
	})
}

func TestEncryptWithID(t *testing.T) {
	Convey("We can encrypt and decrypt messages using an ID", t, func() {
		k, err := generate.Key()
		So(err, ShouldBeNil)
		key := k[:]

		id := uint32(1)

		keyFunc := func(uint32) ([]byte, error) {
			return key, nil
		}
		h := NewGCMHelper(keyFunc)
		data, err := EncryptWithID(key, []byte(text), id)
		So(err, ShouldBeNil)

		So(bytes.Equal([]byte(text), data), ShouldBeFalse)

		data, err = DecryptWithID(data, h)
		So(err, ShouldBeNil)
		So(bytes.Equal([]byte(text), data), ShouldBeTrue)
		s := "You can't read this"
		s1, err := EncryptStringWithID(string(key), s, 47)
		So(err, ShouldBeNil)
		So(s, ShouldNotEqual, s1)

		s1, err = DecryptStringWithID(s1, h)
		So(err, ShouldBeNil)
		So(s1, ShouldEqual, s)

	})
}

func TestCipher_Encrypt(t *testing.T) {
	Convey("We can encrypt and decrypt messages using a cipher struct", t, func() {
		c := New()
		So(c.KeySize(), ShouldEqual, KeySize)
		k, err := generate.Key()
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

var testError = errors.New("test error")

type R struct{}

func (r *R) KeyForID(u uint32) ([]byte, error) {
	return nil, testError
}

type T struct{}

func (t *T) KeyForID(u uint32) ([]byte, error) {
	return []byte{}, nil
}

func TestErrors(t *testing.T) {
	Convey("We can get appropriate errors", t, func() {
		k, err := generate.RandBytes(15)
		So(err, ShouldBeNil)
		key := k[:]
		errText := "crypto/aes: invalid key size 15"
		_, err = Encrypt(key, []byte{})
		So(err.Error(), ShouldEqual, errText)

		_, err = EncryptWithID(key, []byte{}, 1)
		So(err.Error(), ShouldEqual, errText)

		_, err = DecryptWithID([]byte{}, nil)

		k2, err := generate.Key()
		So(err, ShouldBeNil)
		key = k2[:]
		data, err := generate.RandBytes(NonceSize + 5)
		So(err, ShouldBeNil)
		_, err = DecryptWithID(data, &R{})
		So(err, ShouldEqual, testError)

		_, err = DecryptWithID(data, &T{})
		So(err.Error(), ShouldEqual, "crypto/aes: invalid key size 0")

	})
}
