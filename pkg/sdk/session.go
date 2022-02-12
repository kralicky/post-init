package sdk

import (
	"context"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/kex"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type session struct {
	api.UnimplementedWatchServer
	api.UnimplementedKeyExchangeServer

	apiClient api.ClientAPIClient
	conf      *ClientConfig
	kexState  *KeyExchangeState
	notifyC   chan ControlContext
}

var _ api.WatchServer = (*session)(nil)
var _ api.KeyExchangeServer = (*session)(nil)

func (rc *session) ExchangeKeys(ctx context.Context, in *api.KexRequest) (*api.KexResponse, error) {
	priv, pub, err := kex.GenerateKeyPair()
	if err != nil {
		logrus.Fatalf("failed to generate ephemeral key pair: %v", err)
	}

	if err := rc.kexState.Complete(in.ServerEphemeralPublicKey, priv, pub); err != nil {
		return nil, err
	}

	return rc.kexState.KexResponse()
}

func (rc *session) Sign(ctx context.Context, in *api.SignRequest) (*api.SignResponse, error) {
	if !rc.kexState.ExchangeCompleted() {
		return nil, status.Error(codes.FailedPrecondition, "keys have not been exchanged")
	}

	sharedSecret, err := rc.kexState.ComputeSharedSecret()
	if err != nil {
		logrus.Errorf("failed to compute shared secret: %v", err)
		return nil, err
	}

	signature, err := rc.kexState.Sign(rc.conf.Signer, in.Nonce, sharedSecret)
	if err != nil {
		logrus.Errorf("failed to sign kex request: %v", err)
		return nil, err
	}

	return &api.SignResponse{
		Signature: signature,
	}, nil
}

func (rc *session) Notify(ctx context.Context, an *api.Announcement) (*emptypb.Empty, error) {
	ctrlCtx := &controlCtxImpl{
		ctx:          ctx,
		apiClient:    rc.apiClient,
		announcement: an,
	}
	rc.notifyC <- ctrlCtx
	return &emptypb.Empty{}, nil
}
