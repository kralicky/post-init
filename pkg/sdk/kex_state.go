package sdk

import (
	"crypto"
	"fmt"
	"sync"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/kex"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type KeyExchangeState struct {
	serverEphPubKey  []byte
	clientEphPubKey  crypto.PublicKey
	clientEphPrivKey crypto.PrivateKey
	lock             sync.Mutex
}

func NewKeyExchangeState() *KeyExchangeState {
	return &KeyExchangeState{}
}

func (s *KeyExchangeState) Complete(
	serverEphPubKey []byte,
	clientEphPrivKey crypto.PrivateKey,
	clientEphPubKey crypto.PublicKey,
) error {
	if s.ExchangeCompleted() {
		return fmt.Errorf("keys have already been exchanged")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.serverEphPubKey = serverEphPubKey
	s.clientEphPrivKey = clientEphPrivKey
	s.clientEphPubKey = clientEphPubKey
	return nil
}

func (s *KeyExchangeState) ExchangeCompleted() bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.serverEphPubKey != nil &&
		s.clientEphPubKey != nil &&
		s.clientEphPrivKey != nil
}

func (s *KeyExchangeState) KexResponse() (*api.KexResponse, error) {
	if !s.ExchangeCompleted() {
		return nil, status.Error(codes.FailedPrecondition, "keys have not been exchanged")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return &api.KexResponse{
		ClientEphemeralPublicKey: s.clientEphPubKey.([]byte),
	}, nil
}

func (s *KeyExchangeState) ComputeSharedSecret() ([]byte, error) {
	if !s.ExchangeCompleted() {
		return nil, status.Error(codes.FailedPrecondition, "keys have not been exchanged")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return kex.SharedSecret(s.clientEphPrivKey, s.serverEphPubKey)
}

func (s *KeyExchangeState) Sign(signer ssh.Signer, nonce []byte, sharedSecret []byte) ([]byte, error) {
	if !s.ExchangeCompleted() {
		return nil, status.Error(codes.FailedPrecondition, "keys have not been exchanged")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return kex.Sign(signer, nonce, s.serverEphPubKey, s.clientEphPubKey.([]byte), sharedSecret)
}
