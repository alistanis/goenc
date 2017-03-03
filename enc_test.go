package goenc

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"fmt"

	"path/filepath"
	"runtime"

	"reflect"

	"github.com/alistanis/goenc/encerrors"
	"github.com/alistanis/goenc/generate"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/nacl/box"
)

var (
	ciphers []*Cipher
)

func init() {
	cbc, err := NewCipher(CBC, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	cfb, err := NewCipher(CFB, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	ctr, err := NewCipher(CTR, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	gcm, err := NewCipher(GCM, testComplexity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	nacl, err := NewCipher(NaCL, testComplexity, []byte("this is a pad to use for our key mwahahaha 123456789"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	ciphers = []*Cipher{cbc, cfb, ctr, gcm, nacl}
}

func TestFileIO(t *testing.T) {

	Convey("We can successfully perform file writing and reading using the block cipher interface functions", t, func() {
		var tempDir = "/tmp"
		if runtime.GOOS == "windows" {
			userProfile := os.Getenv("USERPROFILE")
			tempDir = filepath.Join(userProfile, "AppData", "Local", "Temp")
		}

		bc, err := NewCipher(Mock, testComplexity)
		So(err, ShouldBeNil)
		d, err := ioutil.TempDir(tempDir, "")
		So(err, ShouldBeNil)
		defer os.RemoveAll(d)
		tf, err := ioutil.TempFile(d, "")
		So(err, ShouldBeNil)

		data := []byte("test data we'd like to 'encrypt' and save to file")
		key := []byte("test key which is meaningless")

		err = EncryptAndSave(bc, key, data, tf.Name())
		So(err, ShouldBeNil)

		err = tf.Close()
		So(err, ShouldBeNil)

		nd, err := ReadEncryptedFile(bc, key, tf.Name())
		So(err, ShouldBeNil)
		So(bytes.Equal(data, nd), ShouldBeTrue)
	})

}

func TestFileIOErrors(t *testing.T) {
	Convey("We can get errors on file io when we should", t, func() {
		c, err := NewCipher(GCM, testComplexity)
		So(err, ShouldBeNil)

		err = EncryptAndSave(c, []byte{}, []byte{}, "")
		So(err, ShouldNotBeNil)

		_, err = ReadEncryptedFile(c, []byte{}, "")
		So(err, ShouldNotBeNil)

		err = EncryptAndSaveWithPerms(c, []byte{}, []byte{}, "", 0644)
		So(err, ShouldNotBeNil)
	})
}

func TestGenerateKeys(t *testing.T) {
	var err error

	_, _, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, _, err = box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestCipher_Encrypt(t *testing.T) {
	Convey("We can test encrypting with a cypher with both keys and passwords", t, func() {
		c, err := NewCipher(GCM, testComplexity)
		So(err, ShouldBeNil)
		k, err := generate.Key()
		So(err, ShouldBeNil)
		key := k[:]
		plaintext := []byte("This is some data")
		data, err := c.Encrypt(key, plaintext)
		So(bytes.Equal(data, plaintext), ShouldBeFalse)

		data, err = c.Decrypt(key, data)
		So(err, ShouldBeNil)
		So(bytes.Equal(data, plaintext), ShouldBeTrue)

		password := []byte("password")
		data, err = c.EncryptWithPassword(password, plaintext)
		So(err, ShouldBeNil)
		So(bytes.Equal(data, plaintext), ShouldBeFalse)

		data, err = c.DecryptWithPassword(password, data)
		So(err, ShouldBeNil)
		So(bytes.Equal(data, plaintext), ShouldBeTrue)
	})
}

func TestDeriveKey(t *testing.T) {
	Convey("We can test a derived key in order to encrypt and decrypt text", t, func() {
		c, err := NewCipher(GCM, testComplexity)
		So(err, ShouldBeNil)

		salt, err := generate.RandBytes(SaltSize)
		So(err, ShouldBeNil)

		key, err := DeriveKey([]byte("password"), salt, c.DerivedKeyN, c.BlockCipher.KeySize())
		So(err, ShouldBeNil)
		plaintext := []byte("This is some data")
		data, err := c.BlockCipher.Encrypt(key, plaintext)
		So(err, ShouldBeNil)

		key2, err := DeriveKey([]byte("password"), salt, c.DerivedKeyN, c.BlockCipher.KeySize())
		So(err, ShouldBeNil)

		data, err = c.BlockCipher.Decrypt(key2, data)
		So(err, ShouldBeNil)
		So(bytes.Equal(plaintext, data), ShouldBeTrue)
	})
}

func TestDeriveKeyErrors(t *testing.T) {
	Convey("We can get derived key errors when we should", t, func() {

		_, err := DeriveKey([]byte{}, []byte{}, 0, 0)
		So(err, ShouldNotBeNil)
	})
}

func TestCiphers(t *testing.T) {
	Convey("We can test all ciphers operate properly", t, func() {
		for _, c := range ciphers {
			k, err := generate.Key()
			So(err, ShouldBeNil)
			nonce, err := generate.Nonce()
			So(err, ShouldBeNil)
			key, err := DeriveKey(k[:], nonce[:], testComplexity, c.KeySize())
			So(err, ShouldBeNil)
			text := []byte("this is some text to encrypt")

			data, err := c.Encrypt(key, text)
			So(err, ShouldBeNil)
			So(bytes.Equal(text, data), ShouldBeFalse)
			data, err = c.Decrypt(key, data)
			So(err, ShouldBeNil)
			So(bytes.Equal(text, data), ShouldBeTrue)
		}
	})
}

func TestMessage(t *testing.T) {
	Convey("We can marshal and unmarshal messages", t, func() {
		m := NewMessage([]byte("Hello!"), 1)
		data := m.Marshal()
		nm, err := UnmarshalMessage(data)
		So(err, ShouldBeNil)
		So(reflect.DeepEqual(m, nm), ShouldBeTrue)

		data = []byte{}

		_, err = UnmarshalMessage(data)
		So(err, ShouldEqual, encerrors.ErrInvalidMessageLength)
	})
}
