package kex

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"errors"
	"io"

	"github.com/kralicky/post-init/pkg/api"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// curve25519-sha256 key exchange
//
// Both the client and server generate an ephemeral key pair and exchange
// public keys, which are used to generate a shared secret. The shared secret
// is signed using the client's private ssh key and sent to the server for
// verification. If the server verifies the signature, the client proves
// ownership of the private key corresponding to the public key it sent
// in the initial exchange.

var ErrInvalidKeyFormat = errors.New("invalid key format")

func GenerateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	private := bytes.NewBuffer(make([]byte, 32))
	if _, err := io.CopyN(private, crand.Reader, 32); err != nil {
		return nil, nil, err
	}

	public, err := curve25519.X25519(curve25519.Basepoint, private.Bytes())
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

// this isn't a real ssh connection so we're improvising a bit on the format

func Sign(
	kexRequest *api.KexRequest,
	clientEphemeralPublicKey crypto.PublicKey,
	publicClientKey []byte,
	sharedSecret []byte,
	sshPrivateKey ssh.Signer,
) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(kexRequest.Nonce)
	buf.Write(kexRequest.PublicHostKey)
	buf.Write(kexRequest.ServerEphemeralPublicKey)
	buf.Write(clientEphemeralPublicKey.([]byte))
	buf.Write(publicClientKey)
	buf.Write(sharedSecret)
	signature, err := sshPrivateKey.Sign(crand.Reader, buf.Bytes())
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(signature), nil
}

func Verify(
	connectionRequest *api.ConnectionRequest,
	kexRequest *api.KexRequest,
	kexResponse *api.KexResponse,
	sharedSecret []byte,
	sshPrivateKey ssh.Signer,
) error {
	buf := new(bytes.Buffer)
	buf.Write(kexRequest.Nonce)
	buf.Write(kexRequest.PublicHostKey)
	buf.Write(kexRequest.ServerEphemeralPublicKey)
	buf.Write(kexResponse.ClientEphemeralPublicKey)
	buf.Write(connectionRequest.PublicClientKey)
	buf.Write(sharedSecret)

	signature := ssh.Signature{}
	if err := ssh.Unmarshal(kexResponse.Signature, &signature); err != nil {
		return err
	}
	publicClientKey, err := ssh.ParsePublicKey(connectionRequest.PublicClientKey)
	if err != nil {
		return err
	}
	return publicClientKey.Verify(buf.Bytes(), &signature)
}
