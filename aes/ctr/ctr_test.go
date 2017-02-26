package ctr

import (
	"bytes"
	"testing"

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
		So(bytes.Equal([]byte(text), data), ShouldBeTrue)
	})
}
