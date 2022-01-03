package postlet

import (
	"context"
	"crypto/tls"
	"os/user"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/host"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type PostletOptions struct {
	relayAddress        string
	relayCACert         string
	insecure            bool
	timeout             time.Duration
	extraAuthorizedKeys []string
}

type PostletOption func(*PostletOptions)

func (o *PostletOptions) Apply(opts ...PostletOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithRelayAddress(addr string) PostletOption {
	return func(o *PostletOptions) {
		o.relayAddress = addr
	}
}

func WithRelayCACert(certFilePath string) PostletOption {
	return func(o *PostletOptions) {
		o.relayCACert = certFilePath
	}
}

func WithInsecure(insecure bool) PostletOption {
	return func(o *PostletOptions) {
		o.insecure = insecure
	}
}

func WithTimeout(d time.Duration) PostletOption {
	return func(o *PostletOptions) {
		o.timeout = d
	}
}

func WithExtraAuthorizedKeys(keys ...string) PostletOption {
	return func(o *PostletOptions) {
		o.extraAuthorizedKeys = keys
	}
}

type Postlet struct {
	options     PostletOptions
	relayClient api.RelayClient
}

func New(opts ...PostletOption) *Postlet {
	options := PostletOptions{}
	options.Apply(opts...)
	return &Postlet{
		options: options,
	}
}

func (d *Postlet) Start(ctx context.Context) error {
	var creds credentials.TransportCredentials
	if d.options.insecure {
		logrus.Warn("POSTLET IS RUNNING IN INSECURE MODE - DO NOT USE IN PRODUCTION")
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

func (d *Postlet) announce(ctx context.Context) error {
	logrus.Infof("Announcing to relay")
	extraKeys := []*api.AuthorizedKey{}
	for _, extraKey := range d.options.extraAuthorizedKeys {
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
		PreferredHostPublicKey: host.GetPreferredHostPublicKey().Marshal(),
		AuthorizedKeys:         append(host.GetAuthorizedKeys(), extraKeys...),
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
	pk, err := ssh.ParsePublicKey(announcement.PreferredHostPublicKey)
	if err != nil {
		return err
	}
	if err := stream.Send(&api.InstructionResponse{
		Fingerprint: ssh.FingerprintSHA256(pk),
	}); err != nil {
		return err
	}

	instructionC := make(chan interface{})
	timer := time.NewTimer(10 * time.Second)
	for {
		go func() {
			rcv, err := stream.Recv()
			if err != nil {
				instructionC <- err
			} else {
				instructionC <- rcv
			}
		}()
		var rcv *api.Instruction
		timer.Reset(10 * time.Second)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case in := <-instructionC:
			switch v := in.(type) {
			case error:
				return v
			case *api.Instruction:
				rcv = v
			}
		case <-timer.C:
			logrus.Warn("Timed out waiting for instructions from relay")
			return stream.CloseSend()
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
