package kex

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// curve25519-sha256 key exchange
//
// Both the client and server generate an ephemeral key pair and exchange
// public keys, which are used to generate a shared secret. The shared secret
// is signed using the client's private ssh key and the signature (sans payload)
// is sent to the server for verification. If the server verifies the signature,
// the client proves ownership of the private key corresponding to the public
// key it sent in the initial exchange.

var ErrInvalidKeyFormat = errors.New("invalid key format")

func GenerateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	private := bytes.NewBuffer(make([]byte, 0, 32))
	if _, err := io.CopyN(private, crand.Reader, 32); err != nil {
		return nil, nil, err
	}

	public, err := curve25519.X25519(private.Bytes(), curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return crypto.PrivateKey(private.Bytes()), crypto.PublicKey(public), nil
}

func SharedSecret(private crypto.PrivateKey, public crypto.PublicKey) ([]byte, error) {
	if s, ok := private.([]byte); !ok || len(s) != 32 {
		return nil, ErrInvalidKeyFormat
	}
	if s, ok := public.([]byte); !ok || len(s) != 32 {
		return nil, ErrInvalidKeyFormat
	}

	return curve25519.X25519(private.([]byte), public.([]byte))
}

func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// this isn't a real ssh connection so we're improvising a bit on the format

func Sign(
	privateKey ssh.Signer,
	nonce []byte,
	serverEphPubKey []byte,
	clientEphPubKey []byte,
	sharedSecret []byte,
) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(nonce)
	buf.Write(serverEphPubKey)
	buf.Write(clientEphPubKey)
	buf.Write(privateKey.PublicKey().Marshal())
	buf.Write(sharedSecret)

	signature, err := privateKey.Sign(crand.Reader, buf.Bytes())
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(signature), nil
}

func Verify(
	clientSignature []byte,
	nonce []byte,
	serverEphPubKey []byte,
	clientEphPubKey []byte,
	clientPublicKey ssh.PublicKey,
	sharedSecret []byte,
) error {
	buf := new(bytes.Buffer)
	buf.Write(nonce)
	buf.Write(serverEphPubKey)
	buf.Write(clientEphPubKey)
	buf.Write(clientPublicKey.Marshal())
	buf.Write(sharedSecret)

	signature := ssh.Signature{}
	if err := ssh.Unmarshal(clientSignature, &signature); err != nil {
		return err
	}

	return clientPublicKey.Verify(buf.Bytes(), &signature)
}
