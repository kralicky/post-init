package daemon

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/host"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type DaemonOptions struct {
	relayAddress string
	relayCACert  string
	insecure     bool
	timeout      time.Duration
}

type DaemonOption func(*DaemonOptions)

func (o *DaemonOptions) Apply(opts ...DaemonOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithRelayAddress(addr string) DaemonOption {
	return func(o *DaemonOptions) {
		o.relayAddress = addr
	}
}

func WithRelayCACert(certFilePath string) DaemonOption {
	return func(o *DaemonOptions) {
		o.relayCACert = certFilePath
	}
}

func WithInsecure(insecure bool) DaemonOption {
	return func(o *DaemonOptions) {
		o.insecure = insecure
	}
}

func WithTimeout(d time.Duration) DaemonOption {
	return func(o *DaemonOptions) {
		o.timeout = d
	}
}

type Daemon struct {
	options     DaemonOptions
	relayClient api.RelayClient
}

func NewDaemon(opts ...DaemonOption) *Daemon {
	options := DaemonOptions{}
	options.Apply(opts...)
	return &Daemon{
		options: options,
	}
}

func (d *Daemon) Start(ctx context.Context) error {
	var creds credentials.TransportCredentials
	if d.options.insecure {
		logrus.Warn("POST-INIT DAEMON IS RUNNING IN INSECURE MODE - DO NOT USE IN PRODUCTION")
		creds = insecure.NewCredentials()
	} else {
		if d.options.relayCACert != "" {
			// Use custom ca cert
			logrus.Infof("Using CA cert from %s", d.options.relayCACert)
			var err error
			creds, err = credentials.NewClientTLSFromFile(d.options.relayCACert, "")
			if err != nil {
				return err
			}
		} else {
			// Use system ca certs
			creds = credentials.NewTLS(&tls.Config{})
		}
	}
	logrus.Info("Connecting to relay at ", d.options.relayAddress)
	cc, err := grpc.DialContext(ctx, d.options.relayAddress,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		return err
	}
	defer cc.Close()
	logrus.Info("Connected")
	d.relayClient = api.NewRelayClient(cc)
	return d.announce(ctx)
}

func (d *Daemon) announce(ctx context.Context) error {
	logrus.Infof("Announcing to relay")
	announcement := &api.Announcement{
		Uname:                  host.GetUnameInfo(),
		Network:                host.GetNetworkInfo(),
		PreferredHostPublicKey: host.GetPreferredHostPublicKey().Marshal(),
		AuthorizedKeys:         host.GetAuthorizedKeys(),
	}

	actx, ca := context.WithTimeout(ctx, d.options.timeout)
	defer ca()
	response, err := d.relayClient.Announce(actx, announcement)
	if err != nil {
		return err
	}
	if response.Accept {
		logrus.Info("Accepted by relay")
		if response.Message != "" {
			logrus.Infof("[RELAY]: %s", response.Message)
		}
	} else {
		logrus.Error("Rejected by relay")
		if response.Message != "" {
			logrus.Errorf("[RELAY]: %s", response.Message)
		}
		return nil
	}

	logrus.Info("Listening for instructions from relay")
	stream, err := d.relayClient.StreamInstructions(ctx)
	if err != nil {
		return err
	}
	for {
		rcv, err := stream.Recv()
		if err != nil {
			return err
		}
		switch in := rcv.Instruction.(type) {
		case *api.Instruction_Dismiss:
			logrus.Info("Dismissed")
			return stream.CloseSend()
		case *api.Instruction_Command:
			logrus.Info("Received command from relay")
			output, err := RunCommand(in.Command)
			if err != nil {
				logrus.Errorf("Error running command: %s", err)
				if err := stream.Send(&api.InstructionResponse{
					Result: api.Result_Error,
					Error:  err.Error(),
				}); err != nil {
					return err
				}
			} else {
				logrus.Info("Command completed successfully")
				if err := stream.Send(&api.InstructionResponse{
					Result: api.Result_Success,
					Instruction: &api.InstructionResponse_CommandOutput{
						CommandOutput: output,
					},
				}); err != nil {
					return err
				}
			}
		case *api.Instruction_Script:
			logrus.Info("Received script from relay")
			output, err := RunScript(in.Script)
			if err != nil {
				logrus.Errorf("Error running script: %s", err)
				if err := stream.Send(&api.InstructionResponse{
					Result: api.Result_Error,
					Error:  err.Error(),
				}); err != nil {
					return err
				}
			} else {
				logrus.Info("Script completed successfully")
				if err := stream.Send(&api.InstructionResponse{
					Result: api.Result_Success,
					Instruction: &api.InstructionResponse_ScriptOutput{
						ScriptOutput: output,
					},
				}); err != nil {
					return err
				}
			}
		}
	}
}
