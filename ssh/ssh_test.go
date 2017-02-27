package ssh

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"io/ioutil"

	"os"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSSHKeyPair(t *testing.T) {
	Convey("We can get private and public ssh key pair bytes", t, func() {

		privBytes, pubBytes, err := PrivateAndPublicKeyBytes(RSA1024)
		So(err, ShouldBeNil)

		_, err = ssh.ParsePrivateKey(privBytes)
		So(err, ShouldBeNil)

		_, err = ssh.ParsePublicKey(pubBytes)
		So(err, ShouldBeNil)

		privBytes, pubBytes, err = LocalKeyPair(RSA1024)
		So(err, ShouldBeNil)

		_, _, _, _, err = ssh.ParseAuthorizedKey(pubBytes)
		So(err, ShouldBeNil)
	})
}

func TestSaveNewKeyPair(t *testing.T) {
	Convey("We can generate and save keys to local files", t, func() {
		dir, err := ioutil.TempDir("/tmp", "")
		So(err, ShouldBeNil)

		t1, err := ioutil.TempFile(dir, "")
		So(err, ShouldBeNil)
		t2, err := ioutil.TempFile(dir, "")
		So(err, ShouldBeNil)

		err = SaveNewKeyPair(t1.Name(), t2.Name(), RSA1024)
		So(err, ShouldBeNil)

		err = os.RemoveAll(dir)
		So(err, ShouldBeNil)
	})
}

func TestErrors(t *testing.T) {
	Convey("We can get errors when we should", t, func() {
		_, _, err := LocalKeyPair(1)
		So(err, ShouldNotBeNil)
		_, _, err = PrivateAndPublicKeyBytes(1)
		So(err, ShouldNotBeNil)

		err = SaveNewKeyPair("", "", 1)
		So(err, ShouldNotBeNil)
	})
}
