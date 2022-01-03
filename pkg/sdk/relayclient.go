package sdk

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/kex"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type ClientConfig struct {
	// The address of the relay server (ip:port or fqdn:port)
	Address string
	// Whether to connect to the relay in insecure mode (testing only)
	Insecure bool
	// Path to a CA Cert if the relay is using a self-signed certificate
	CACert string
	// SSH keypair which the relay server will verify and use to
	// authenticate the client with any daemons that connect.
	Signer ssh.Signer
}

type RelayClient struct {
	conf      *ClientConfig
	client    api.RelayClient
	clientId  string
	callbacks []NotifyCallback
}

func NewRelayClient(conf *ClientConfig) (*RelayClient, error) {
	return &RelayClient{
		conf: conf,
	}, nil
}

func (rc *RelayClient) Connect(ctx context.Context) error {
	var creds credentials.TransportCredentials
	if rc.conf.Insecure {
		creds = insecure.NewCredentials()
	} else {
		if rc.conf.CACert != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(rc.conf.CACert, "")
			if err != nil {
				return err
			}
		} else {
			creds = credentials.NewTLS(&tls.Config{})
		}
	}
	cc, err := grpc.DialContext(ctx, rc.conf.Address,
		grpc.WithTransportCredentials(creds), grpc.WithBlock())
	if err != nil {
		return err
	}

	rc.client = api.NewRelayClient(cc)
	stream, err := rc.client.ClientConnect(ctx)
	if err != nil {
		return err
	}

	connectionRequest := &api.ConnectionRequest{
		PublicClientKey: rc.conf.Signer.PublicKey().Marshal(),
	}
	if err := stream.Send(&api.ClientConnectRequest{
		Request: &api.ClientConnectRequest_ConnectionRequest{
			ConnectionRequest: connectionRequest,
		},
	}); err != nil {
		return err
	}
	r, err := stream.Recv()
	if err != nil {
		return err
	}
	if resp, ok := r.Response.(*api.ClientConnectResponse_ConnectionResponse); ok {
		if resp.ConnectionResponse.Accept {
			go rc.handleConnectionStream(ctx, stream)
		} else {
			return fmt.Errorf("connection rejected")
		}
	} else {
		return fmt.Errorf("unexpected response type: %T", r.Response)
	}

	return nil
}

func (rc *RelayClient) handleConnectionStream(
	ctx context.Context,
	stream api.Relay_ClientConnectClient,
) {
	for {
		r, err := stream.Recv()
		if err != nil {
			return
		}
		switch r := r.GetResponse().(type) {
		case *api.ClientConnectResponse_NotifyResponse:
			resp := r.NotifyResponse
			go func() {
				cctx := &ControlContext{
					ctx:    stream.Context(),
					client: rc.client,
					fp:     resp.GetFingerprint(),
					an:     resp.GetAnnouncement(),
				}
				for _, callback := range rc.callbacks {
					go callback(cctx)
				}
				if !cctx.dismissed {
					if err := cctx.Dismiss(); err != nil {
						logrus.Errorf("Failed to dismiss: %v", err)
					}
				}
			}()
		case *api.ClientConnectResponse_KexRequest:
			kr := r.KexRequest

			ephPriv, ephPub, err := kex.GenerateKeyPair()
			if err != nil {
				logrus.Fatalf("failed to generate ephemeral key pair: %v", err)
			}

			sharedSecret, err := kex.SharedSecret(ephPriv, kr.ServerEphemeralPublicKey)
			if err != nil {
				logrus.Errorf("failed to compute shared secret: %v", err)
				return
			}

			signature, err := kex.Sign(
				r.KexRequest,
				ephPub,
				rc.conf.Signer.PublicKey().Marshal(),
				sharedSecret,
				rc.conf.Signer,
			)

			if err != nil {
				logrus.Errorf("failed to sign kex request: %v", err)
				return
			}

			if err := stream.Send(&api.ClientConnectRequest{
				Request: &api.ClientConnectRequest_KexResponse{
					KexResponse: &api.KexResponse{
						ClientEphemeralPublicKey: ephPub.([]byte),
						Signature:                signature,
					},
				},
			}); err != nil {
				logrus.Errorf("failed to send kex response: %v", err)
				return
			}
		}
	}
}

var ErrAlreadyDismissed = fmt.Errorf("already dismissed")

type ControlContext struct {
	ctx       context.Context
	client    api.RelayClient
	fp        string
	an        *api.Announcement
	dismissed bool
}

func (cc *ControlContext) Announcement() *api.Announcement {
	return cc.an
}

func (cc *ControlContext) RunCommand(cmd *api.Command) (*api.CommandOutput, error) {
	if cc.dismissed {
		return nil, ErrAlreadyDismissed
	}
	if err := cc.ctx.Err(); err != nil {
		return nil, err
	}
	resp, err := cc.client.SendInstruction(cc.ctx, &api.InstructionRequest{
		Fingerprint: cc.fp,
		Instruction: &api.Instruction{
			Instruction: &api.Instruction_Command{
				Command: cmd,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return resp.GetCommandOutput(), nil
}

func (cc *ControlContext) RunScript(sc *api.Script) (*api.ScriptOutput, error) {
	if cc.dismissed {
		return nil, ErrAlreadyDismissed
	}
	if err := cc.ctx.Err(); err != nil {
		return nil, err
	}
	resp, err := cc.client.SendInstruction(cc.ctx, &api.InstructionRequest{
		Fingerprint: cc.fp,
		Instruction: &api.Instruction{
			Instruction: &api.Instruction_Script{
				Script: sc,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return resp.GetScriptOutput(), nil
}

func (cc *ControlContext) Dismiss() error {
	if !cc.dismissed {
		cc.dismissed = true
	} else if err := cc.ctx.Err(); err != nil {
		cc.dismissed = true
		return err
	} else {
		return nil
	}
	_, err := cc.client.SendInstruction(cc.ctx, &api.InstructionRequest{
		Fingerprint: cc.fp,
		Instruction: &api.Instruction{
			Instruction: &api.Instruction_Dismiss{
				Dismiss: &api.Dismiss{},
			},
		},
	})
	return err
}

type NotifyCallback func(*ControlContext)

func (rc *RelayClient) Notify(
	ctx context.Context,
	filter *api.BasicFilter,
	callback NotifyCallback,
) error {
	response, err := rc.client.Notify(ctx, &api.NotifyRequest{
		ClientId: rc.clientId,
	})
	if err != nil {
		return err
	}
	if !response.Accept {
		return fmt.Errorf("server rejected notify request")
	}
	rc.callbacks = append(rc.callbacks, callback)
	return nil
}
