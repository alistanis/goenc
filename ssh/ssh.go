package ssh

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// SSHKeyPair generates private and public key bytes
func SSHKeyPair() (privateKeyBytes, publicKeyBytes []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer(privateKeyBytes)
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err = pem.Encode(buf, privateKeyPEM); err != nil {
		return nil, nil, err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeyBytes = ssh.MarshalAuthorizedKey(pub)
	return
}

// GenerateAndSaveSSHKeyPair generates a new ssh private key and public key and saves them to the given paths
func GenerateAndSaveSSHKeyPair(privateKeyPath, pubkeyPath string) error {
	pr, pub, err := SSHKeyPair()
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(privateKeyPath, pr, 0600); err != nil {
		return err
	}
	return ioutil.WriteFile(pubkeyPath, pub, 0644)
}
