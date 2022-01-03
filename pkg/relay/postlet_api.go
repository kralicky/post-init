package relay

import (
	context "context"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type postletApiServer struct {
	api.UnimplementedPostletAPIServer
	ctrl Controller

	// Filled in by the relay server
	instructionClient api.InstructionClient

	// Closes when an announcement has been received.
	anRecv chan struct{}
}

func NewPostletAPIServer(ctrl Controller) *postletApiServer {
	return &postletApiServer{
		ctrl:   ctrl,
		anRecv: make(chan struct{}),
	}
}

func (s *postletApiServer) InitClients(cc grpc.ClientConnInterface) {
	s.instructionClient = api.NewInstructionClient(cc)
}

func (s *postletApiServer) Announce(
	ctx context.Context,
	an *api.Announcement,
) (*api.AnnouncementResponse, error) {
	logrus.Info("Announcement received")

	if _, err := an.Fingerprint(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	close(s.anRecv)
	s.ctrl.PostletConnected(ctx, an, s.instructionClient)

	return &api.AnnouncementResponse{
		Accept:  true,
		Message: "Hello world",
	}, nil
}

func (s *postletApiServer) AnnouncementReceived() <-chan struct{} {
	return s.anRecv
}
