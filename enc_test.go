package goenc

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
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

		err = BCEncryptAndSave(bc, key, data, tf.Name())
		So(err, ShouldBeNil)

		err = tf.Close()
		So(err, ShouldBeNil)

		nd, err := BCReadEncryptedFile(bc, key, tf.Name())
		So(err, ShouldBeNil)
		So(bytes.Equal(data, nd), ShouldBeTrue)
	})

}
