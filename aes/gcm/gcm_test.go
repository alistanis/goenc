package gcm

import (
	"bytes"
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
		h := NewHelper(keyFunc)
		data, err := EncryptWithID(key, []byte(text), id)
		So(err, ShouldBeNil)

		So(bytes.Equal([]byte(text), data), ShouldBeFalse)

		data, err = DecryptWithID(data, h)
		So(err, ShouldBeNil)
		So(bytes.Equal([]byte(text), data), ShouldBeTrue)
	})
}
