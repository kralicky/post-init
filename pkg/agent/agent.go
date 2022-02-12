package agent

import (
	"context"
	"crypto/tls"
	"os/user"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/host"
	"github.com/kralicky/post-init/pkg/util"
	"github.com/kralicky/totem"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type AgentOptions struct {
	relayAddress        string
	relayCACert         string
	insecure            bool
	timeout             time.Duration
	extraAuthorizedKeys []string
}

type AgentOption func(*AgentOptions)

func (o *AgentOptions) Apply(opts ...AgentOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithRelayAddress(addr string) AgentOption {
	return func(o *AgentOptions) {
		o.relayAddress = addr
	}
}

func WithRelayCACert(certFilePath string) AgentOption {
	return func(o *AgentOptions) {
		o.relayCACert = certFilePath
	}
}

func WithInsecure(insecure bool) AgentOption {
	return func(o *AgentOptions) {
		o.insecure = insecure
	}
}

func WithTimeout(d time.Duration) AgentOption {
	return func(o *AgentOptions) {
		o.timeout = d
	}
}

func WithExtraAuthorizedKeys(keys ...string) AgentOption {
	return func(o *AgentOptions) {
		o.extraAuthorizedKeys = keys
	}
}

type Agent struct {
	api.UnimplementedInstructionServer
	options     AgentOptions
	relayClient api.RelayClient
	sharedTimer *util.SharedTimer
}

func New(opts ...AgentOption) *Agent {
	options := AgentOptions{}
	options.Apply(opts...)
	return &Agent{
		options: options,
	}
}

func (a *Agent) Start(ctx context.Context) error {
	var creds credentials.TransportCredentials
	if a.options.insecure {
		logrus.Warn("AGENT IS RUNNING IN INSECURE MODE - DO NOT USE IN PRODUCTION")
		creds = insecure.NewCredentials()
	} else {
		if a.options.relayCACert != "" {
			// Use custom ca cert
			logrus.Infof("Using CA cert from %s", a.options.relayCACert)
			var err error
			creds, err = credentials.NewClientTLSFromFile(a.options.relayCACert, "")
			if err != nil {
				return err
			}
		} else {
			// Use system ca certs
			creds = credentials.NewTLS(&tls.Config{})
		}
	}
	logrus.Info("Connecting to relay at ", a.options.relayAddress)
	cc, err := grpc.DialContext(ctx, a.options.relayAddress,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		return err
	}
	defer cc.Close()
	logrus.Info("Connected")
	a.relayClient = api.NewRelayClient(cc)
	return a.announce(ctx)
}

func (a *Agent) announce(ctx context.Context) error {
	logrus.Infof("Announcing to relay")
	extraKeys := []*api.AuthorizedKey{}
	for _, extraKey := range a.options.extraAuthorizedKeys {
		key, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(extraKey))
		if err != nil {
			return err
		}
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		extraKeys = append(extraKeys, &api.AuthorizedKey{
			User:        currentUser.Name,
			Type:        key.Type(),
			Fingerprint: ssh.FingerprintSHA256(key),
			Comment:     comment,
			Options:     options,
		})
	}
	announcement := &api.Announcement{
		Uname:                  host.GetUnameInfo(),
		Network:                host.GetNetworkInfo(),
		PreferredHostPublicKey: ssh.MarshalAuthorizedKey(host.GetPreferredHostPublicKey()),
		AuthorizedKeys:         append(host.GetAuthorizedKeys(), extraKeys...),
	}
	stream, err := a.relayClient.AgentStream(ctx)
	if err != nil {
		return err
	}
	ts := totem.NewServer(stream)
	api.RegisterInstructionServer(ts, a)
	clientConn, _ := ts.Serve()
	apiClient := api.NewAgentAPIClient(clientConn)
	_, err = apiClient.Announce(ctx, announcement)
	if err != nil {
		return err
	}
	logrus.Info("Successfully announced to relay")
	a.sharedTimer = util.NewSharedTimer(a.options.timeout)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.sharedTimer.C():
		logrus.Infof("No commands received within %s, exiting", a.options.timeout)
		return nil
	}
}

func (a *Agent) Command(ctx context.Context, req *api.CommandRequest) (*api.CommandResponse, error) {
	logrus.Infof("Executing command %s", req.Command)
	a.sharedTimer.Block()
	defer a.sharedTimer.Unblock()
	return RunCommand(req.Command)
}

func (a *Agent) Script(ctx context.Context, req *api.ScriptRequest) (*api.ScriptResponse, error) {
	logrus.Infof("Executing script %s", req.Script)
	a.sharedTimer.Block()
	defer a.sharedTimer.Unblock()
	return RunScript(req.Script)
}
