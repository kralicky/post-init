package sdk

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"

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
	KeyPair KeyPair
}

type KeyPair struct {
	PublicKey      ssh.PublicKey
	PrivateKeyPath string
}

type RelayClient struct {
	conf *ClientConfig
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

	relayClient := api.NewRelayClient(cc)
	stream, err := relayClient.ClientConnect(ctx)
	if err != nil {
		return err
	}

	connectionRequest := &api.ConnectionRequest{
		PublicClientKey: rc.conf.KeyPair.PublicKey.Marshal(),
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
		case *api.ClientConnectResponse_KexRequest:
			kr := r.KexRequest

			privateKeyData, err := os.ReadFile(rc.conf.KeyPair.PrivateKeyPath)
			if err != nil {
				logrus.Errorf("failed to read private key: %v", err)
				return
			}
			privateKey, err := ssh.ParsePrivateKey(privateKeyData)
			if err != nil {
				logrus.Errorf("failed to parse private key: %v", err)
				return
			}

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
				rc.conf.KeyPair.PublicKey.Marshal(),
				sharedSecret,
				privateKey,
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
