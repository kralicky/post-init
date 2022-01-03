package relay

import (
	context "context"
	"net"
	"time"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/totem"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
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

type Server struct {
	api.UnimplementedRelayServer
	options RelayServerOptions

	ctrl Controller
}

func NewRelayServer(opts ...RelayServerOption) *Server {
	options := RelayServerOptions{
		listenAddress: ":9292",
	}
	options.Apply(opts...)
	return &Server{
		ctrl:    NewController(),
		options: options,
	}
}

func (rs *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", rs.options.listenAddress)
	if err != nil {
		return err
	}
	logrus.Infof("Listening on %s", listener.Addr().String())
	options := []grpc.ServerOption{}
	if rs.options.insecure {
		options = append(options, grpc.Creds(insecure.NewCredentials()))
		logrus.Warn("RELAY IS RUNNING IN INSECURE MODE - DO NOT USE IN PRODUCTION")
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

func (rs *Server) PostletStream(stream api.Relay_PostletStreamServer) error {
	ts := totem.NewServer(stream)

	server := NewPostletAPIServer(rs.ctrl)
	api.RegisterPostletAPIServer(ts, server)

	cond := make(chan struct{})
	cc, errC := ts.Serve(cond)
	server.InitClients(cc)
	close(cond)

	select {
	case <-server.AnnouncementReceived():
		err := <-errC
		return err
	case <-time.After(time.Second * 5):
		return status.Error(codes.DeadlineExceeded, "timed out waiting for announcement")
	case <-errC:
		return status.Error(codes.Aborted, "stream error")
	}
}

func (rs *Server) ClientStream(stream api.Relay_ClientStreamServer) error {
	ts := totem.NewServer(stream)

	server := NewClientAPIServer(rs.ctrl)
	api.RegisterClientAPIServer(ts, server)

	cond := make(chan struct{})
	cc, errC := ts.Serve(cond)
	server.InitClients(cc)
	close(cond)

	return <-errC
}
