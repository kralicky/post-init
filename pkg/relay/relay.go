package relay

import (
	"bytes"
	context "context"
	crand "crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type RelayServerOptions struct {
	listenAddress string
	servingCert   string
	servingKey    string
	insecure      bool
}

type RelayServerOption func(*RelayServerOptions)

func (o *RelayServerOptions) Apply(opts ...RelayServerOption) {
	for _, op := range opts {
		op(o)
	}
}

func ListenAddress(addr string) RelayServerOption {
	return func(o *RelayServerOptions) {
		o.listenAddress = addr
	}
}

func ServingCerts(cert, key string) RelayServerOption {
	return func(o *RelayServerOptions) {
		o.servingCert = cert
		o.servingKey = key
	}
}

func Insecure(insecure bool) RelayServerOption {
	return func(o *RelayServerOptions) {
		o.insecure = insecure
	}
}

type activeDaemon struct {
	Announcement *api.Announcement
	Stream       api.Relay_StreamInstructionsServer
	Instructions chan *activeInstruction
}

type activeInstruction struct {
	Instruction *api.Instruction
	ResponseC   chan *api.InstructionResponse
}

type Server struct {
	api.UnimplementedRelayServer
	options RelayServerOptions

	activeDaemonsLock sync.Mutex
	activeDaemons     map[string]activeDaemon
}

func NewRelayServer(opts ...RelayServerOption) *Server {
	options := RelayServerOptions{
		listenAddress: ":9292",
	}
	options.Apply(opts...)
	return &Server{
		options: options,
	}
}

func (rs *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", rs.options.listenAddress)
	if err != nil {
		return err
	}
	logrus.Infof("Listening on %s", rs.options.listenAddress)
	options := []grpc.ServerOption{}
	if rs.options.insecure {
		options = append(options, grpc.Creds(insecure.NewCredentials()))
		logrus.Warn("POST-INIT SERVER IS RUNNING IN INSECURE MODE - DO NOT USE IN PRODUCTION")
	} else {
		creds, err := credentials.NewServerTLSFromFile(
			rs.options.servingCert, rs.options.servingKey)
		if err != nil {
			return err
		}
		options = append(options, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(options...)
	api.RegisterRelayServer(grpcServer, rs)
	return grpcServer.Serve(listener)
}

func (rs *Server) Announce(
	ctx context.Context,
	an *api.Announcement,
) (*api.Response, error) {
	logrus.Info("Announcement received")

	rs.activeDaemonsLock.Lock()
	pubKey, err := ssh.ParsePublicKey(an.PreferredHostPublicKey)
	if err != nil {
		return nil, err
	}
	fingerprint := ssh.FingerprintSHA256(pubKey)
	rs.activeDaemons[fingerprint] = activeDaemon{
		Announcement: an,
	}
	rs.activeDaemonsLock.Unlock()

	return &api.Response{
		Accept:  true,
		Message: "Hello world",
	}, nil
}

func (rs *Server) StreamInstructions(
	stream api.Relay_StreamInstructionsServer,
) error {
	logrus.Info("Streaming instructions for daemon")
	r, err := stream.Recv()
	if err != nil {
		return err
	}
	if r.Fingerprint == "" {
		return status.Error(codes.FailedPrecondition, "daemon did not send fingerprint")
	}

	instructionsC := make(chan *activeInstruction)
	rs.activeDaemonsLock.Lock()
	if daemon, ok := rs.activeDaemons[r.Fingerprint]; ok {
		daemon.Stream = stream
		daemon.Instructions = instructionsC
		rs.activeDaemons[r.Fingerprint] = daemon
	} else {
		logrus.Error("error: daemon did not announce")
		return status.Error(codes.FailedPrecondition, "daemon did not announce")
	}
	rs.activeDaemonsLock.Unlock()

	timeout := time.After(10 * time.Second)

LOOP:
	for {
		select {
		case <-timeout:
			break LOOP
		case instruction := <-instructionsC:
			err := stream.Send(instruction.Instruction)
			if err != nil {
				instruction.ResponseC <- &api.InstructionResponse{
					Result: api.Result_Error,
					Error:  err.Error(),
				}
			} else {
				response, err := stream.Recv()
				if err != nil {
					instruction.ResponseC <- &api.InstructionResponse{
						Result: api.Result_Error,
						Error:  err.Error(),
					}
				} else {
					instruction.ResponseC <- response
				}
			}
		}
	}
	return dismiss(stream)
}

func (rs *Server) Notify(
	match *api.NotifyMatch,
	stream api.Relay_NotifyServer,
) error {
	// todo
	return nil
}

func (rs *Server) SendInstruction(
	ctx context.Context,
	instruction *api.Instruction,
) (*api.InstructionResponse, error) {
	// todo
	return nil, nil
}

func (rs *Server) ClientConnect(
	stream api.Relay_ClientConnectServer,
) error {
	logrus.Info("Client connected")
	nonce := bytes.NewBuffer(make([]byte, 32))
	io.CopyN(nonce, crand.Reader, 32)

	r, err := stream.Recv()
	if err != nil {
		return err
	}
	var connectionRequest *api.ConnectionRequest
	if cr, ok := r.Request.(*api.ClientConnectRequest_ConnectionRequest); ok {
		connectionRequest = cr.ConnectionRequest
		stream.Send(&api.ClientConnectResponse{
			Response: &api.ClientConnectResponse_ConnectionResponse{
				ConnectionResponse: &api.ConnectionResponse{
					Accept: true,
				},
			},
		})
	}

	connectionRequest.String()
	// todo
	return nil
}

func dismiss(stream api.Relay_StreamInstructionsServer) error {
	if err := stream.Send(&api.Instruction{
		Instruction: &api.Instruction_Dismiss{},
	}); err != nil {
		return err
	}
	_, err := stream.Recv()
	return err
}
