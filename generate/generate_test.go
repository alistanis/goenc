package generate

import (
	"bytes"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestKey(t *testing.T) {
	Convey("We can get a random key", t, func() {
		k, err := Key()
		So(err, ShouldBeNil)
		So(len(k[:]), ShouldEqual, KeySize)
		k2, err := Key()
		So(err, ShouldBeNil)
		So(len(k2[:]), ShouldEqual, KeySize)
		So(bytes.Equal(k[:], k2[:]), ShouldBeFalse)
	})
}

func TestNonce(t *testing.T) {
	Convey("We can get a random nonce", t, func() {
		n, err := Nonce()
		So(err, ShouldBeNil)
		So(len(n[:]), ShouldEqual, NonceSize)
		n2, err := Nonce()
		So(err, ShouldBeNil)
		So(len(n2[:]), ShouldEqual, NonceSize)
		So(bytes.Equal(n[:], n2[:]), ShouldBeFalse)
	})
}

func TestRandBytes(t *testing.T) {
	Convey("We can get random bytes", t, func() {
		b, err := RandBytes(KeySize)
		So(err, ShouldBeNil)
		b2, err := RandBytes(KeySize)
		So(err, ShouldBeNil)
		So(bytes.Equal(b, b2), ShouldBeFalse)
	})
}

func TestRandString(t *testing.T) {
	Convey("We can get a random string", t, func() {
		s, err := RandString(3)
		So(err, ShouldBeNil)
		s2, err := RandString(3)
		So(err, ShouldBeNil)
		So(s, ShouldNotEqual, s2)
	})
}
