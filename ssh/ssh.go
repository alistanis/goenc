// Package ssh supports generation of key pairs in different formats with as few parameters as possible
package ssh

import (
	"crypto/rand"
	"crypto/rsa"

	"bytes"
	"crypto/x509"
	"encoding/pem"

	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

const (
	// RSA1024 is 1024 bits (should only be used for testing)
	RSA1024 = 1 << (10 + iota)
	// RSA2048 is 2048 bits
	RSA2048
	// RSA4096 is 4096 bits
	RSA4096
)

// LocalKeyPair returns bits formatted for a local ssh key pair (id_rsa, id_rsa.pub - AuthorizedKey format)
func LocalKeyPair(bits int) (private, public []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(buf, privateKeyPEM); err != nil {
		return nil, nil, err
	}
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), ssh.MarshalAuthorizedKey(pub), nil
}

// PrivateAndPublicKeyBytes takes a privateKey and returns the private and public key bytes, the public key bytes
// are in the wire format protocol
func PrivateAndPublicKeyBytes(bits int) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(buf, privateKeyPEM); err != nil {
		return nil, nil, err
	}

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), pub.Marshal(), err
}

// SaveNewKeyPair generates a new key and saves private and public keys to a local path with the given bit
func SaveNewKeyPair(privPath, pubPath string, bits int) error {
	priv, pub, err := LocalKeyPair(bits)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(privPath, priv, 0600)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(pubPath, pub, 0644)
}

// ReadLocalPublicKey reads a local path for a public key stored in the AuthorizedKeys format
func ReadLocalPublicKey(pubPath string) (out ssh.PublicKey, comment string, options []string, rest []byte, err error) {
	data, err := ioutil.ReadFile(pubPath)
	if err != nil {
		return nil, "", nil, nil, err
	}
	return ssh.ParseAuthorizedKey(data)
}
