package goenc

import (
	"fmt"
	"testing"

	"crypto/rand"

	"bytes"

	. "github.com/smartystreets/goconvey/convey"
)

func TestEncryptDecrypt(t *testing.T) {
	Convey("We can test encrypting and decrpyting bytes and strings", t, func() {
		s := "this is a test string to encrypt"
		key := make([]byte, 32)
		_, err := rand.Read(key)
		So(err, ShouldBeNil)

		es, err := EncryptString(s, string(key))
		So(err, ShouldBeNil)
		So(s, ShouldNotEqual, es)

		ds, err := DecryptString(es, string(key))
		So(err, ShouldBeNil)
		So(ds, ShouldEqual, s)
	})

	Convey("We can test encrypting and decrypting bytes using secretbox (NaCL)", t, func() {
		pad := make([]byte, 32)
		_, err := rand.Read(pad)
		So(err, ShouldBeNil)

		b := []byte("This is a message we'd like to encrypt")
		k := []byte("super weak key")

		out, err := NaCLEncrypt(pad, k, b)
		So(err, ShouldBeNil)
		So(bytes.Equal(b, out), ShouldBeFalse)

		msg, err := NaCLDecrypt(pad, k, out)
		So(err, ShouldBeNil)

		So(bytes.Equal(b, msg), ShouldBeTrue)

		pad, out, err = RandomPadNaCLEncrypt(k, b)
		So(bytes.Equal(b, out), ShouldBeFalse)
		msg, err = NaCLDecrypt(pad, k, out)
		So(bytes.Equal(b, msg), ShouldBeTrue)
	})
}

func TestSSHKeyPair(t *testing.T) {

}
