package relay

import (
	context "context"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type agentApiServer struct {
	api.UnimplementedAgentAPIServer
	ctrl Controller

	// Filled in by the relay server
	instructionClient api.InstructionClient

	// Closes when an announcement has been received.
	anRecv chan struct{}
}

func NewAgentAPIServer(ctrl Controller) *agentApiServer {
	return &agentApiServer{
		ctrl:   ctrl,
		anRecv: make(chan struct{}),
	}
}

func (s *agentApiServer) InitClients(cc grpc.ClientConnInterface) {
	s.instructionClient = api.NewInstructionClient(cc)
}

func (s *agentApiServer) Announce(
	ctx context.Context,
	an *api.Announcement,
) (*api.AnnouncementResponse, error) {
	logrus.Info("Announcement received")

	if _, err := an.Fingerprint(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	close(s.anRecv)
	s.ctrl.AgentConnected(ctx, an, s.instructionClient)

	return &api.AnnouncementResponse{
		Accept:  true,
		Message: "Hello world",
	}, nil
}

func (s *agentApiServer) AnnouncementReceived() <-chan struct{} {
	return s.anRecv
}
