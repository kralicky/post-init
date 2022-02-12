package relay

import (
	context "context"
	"fmt"
	"sync"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/kex"
	"golang.org/x/crypto/ssh"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type clientApiServer struct {
	api.UnimplementedClientAPIServer
	ctrl Controller

	// Filled in by the relay server
	watchClient api.WatchClient
	kexClient   api.KeyExchangeClient

	lock        sync.Mutex
	verifiedKey ssh.PublicKey
}

func NewClientAPIServer(ctrl Controller) *clientApiServer {
	return &clientApiServer{
		ctrl: ctrl,
	}
}

func (s *clientApiServer) InitClients(cc grpc.ClientConnInterface) {
	s.watchClient = api.NewWatchClient(cc)
	s.kexClient = api.NewKeyExchangeClient(cc)
}

func (s *clientApiServer) Connect(
	ctx context.Context,
	req *api.ConnectionRequest,
) (*api.ConnectionResponse, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.verifiedKey != nil {
		return nil, status.Error(codes.FailedPrecondition, "already connected")
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(req.PublicClientKey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.verifyClientPublicKey(ctx, pk); err != nil {
		return nil, err
	}
	s.verifiedKey = pk
	s.ctrl.ClientConnected(ctx, pk)
	return &api.ConnectionResponse{}, nil
}

func (s *clientApiServer) Watch(
	ctx context.Context,
	req *api.WatchRequest,
) (*emptypb.Empty, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.verifiedKey == nil {
		return nil, status.Error(codes.FailedPrecondition, "not connected")
	}
	ch, err := s.ctrl.Watch(ctx, s.verifiedKey, req)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case an := <-ch:
				s.watchClient.Notify(ctx, an)
			}
		}
	}()
	return &emptypb.Empty{}, nil
}

func (s *clientApiServer) RunCommand(
	ctx context.Context,
	req *api.CommandRequest,
) (*api.CommandResponse, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.verifiedKey == nil {
		return nil, status.Error(codes.FailedPrecondition, "not connected")
	}
	instructionClient, err := s.ctrl.Lookup(ctx, req.Meta.PeerFingerprint)
	if err != nil {
		return nil, status.Error(codes.NotFound, "peer not found")
	}
	return instructionClient.Command(ctx, req)
}

func (s *clientApiServer) RunScript(
	ctx context.Context,
	req *api.ScriptRequest,
) (*api.ScriptResponse, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.verifiedKey == nil {
		return nil, status.Error(codes.FailedPrecondition, "not connected")
	}
	instructionClient, err := s.ctrl.Lookup(ctx, req.Meta.PeerFingerprint)
	if err != nil {
		return nil, status.Error(codes.NotFound, "peer not found")
	}
	return instructionClient.Script(ctx, req)
}

func (s *clientApiServer) verifyClientPublicKey(ctx context.Context, clientPubKey ssh.PublicKey) error {
	serverEphPriv, serverEphPub, err := kex.GenerateKeyPair()
	if err != nil {
		return status.Error(codes.Internal, "internal server error")
	}

	resp, err := s.kexClient.ExchangeKeys(ctx, &api.KexRequest{
		ServerEphemeralPublicKey: serverEphPub.([]byte),
	})
	if err != nil {
		return status.Error(codes.Aborted, fmt.Sprintf("key exchange failed: %s", err))
	}

	clientEphPub := resp.ClientEphemeralPublicKey
	if len(clientEphPub) != len(serverEphPub.([]byte)) {
		return status.Error(codes.InvalidArgument, "key exchange failed: client sent invalid ephemeral public key")
	}

	sharedSecret, err := kex.SharedSecret(serverEphPriv, clientEphPub)
	if err != nil {
		return status.Error(codes.PermissionDenied, "key validation failed")
	}

	nonce, err := kex.GenerateNonce()
	if err != nil {
		return status.Error(codes.Internal, "internal server error")
	}

	sig, err := s.kexClient.Sign(ctx, &api.SignRequest{
		Nonce: nonce,
	})
	if err != nil {
		return status.Error(codes.Aborted, fmt.Sprintf("key exchange failed: %s", err))
	}

	// verify the signature
	err = kex.Verify(sig.Signature, nonce, serverEphPub.([]byte), clientEphPub, clientPubKey, sharedSecret)
	if err != nil {
		return status.Error(codes.PermissionDenied, "key validation failed")
	}

	return nil
}
