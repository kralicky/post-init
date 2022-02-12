package sdk

import (
	"context"
	"crypto/tls"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/totem"
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
	conf        *ClientConfig
	relayClient api.RelayClient
	apiClient   api.ClientAPIClient
	callbacks   []NotifyCallback
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

	rc.relayClient = api.NewRelayClient(cc)
	stream, err := rc.relayClient.ClientStream(ctx)
	if err != nil {
		return err
	}
	ts := totem.NewServer(stream)

	ch := make(chan ControlContext)
	session := &session{
		conf:      rc.conf,
		apiClient: rc.apiClient,
		kexState:  NewKeyExchangeState(),
		notifyC:   ch,
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case cc := <-ch:
				for _, cb := range rc.callbacks {
					go cb(cc)
				}
			}
		}
	}()

	api.RegisterWatchServer(ts, session)
	api.RegisterKeyExchangeServer(ts, session)
	clientConn, _ := ts.Serve()

	rc.apiClient = api.NewClientAPIClient(clientConn)
	if _, err := rc.apiClient.Connect(ctx, &api.ConnectionRequest{
		PublicClientKey: ssh.MarshalAuthorizedKey(rc.conf.Signer.PublicKey()),
	}); err != nil {
		return err
	}
	return nil
}

func (rc *RelayClient) Watch(
	ctx context.Context,
	filter *api.BasicFilter,
	callback NotifyCallback,
) error {
	rc.callbacks = append(rc.callbacks, callback) // todo: fix this logic
	_, err := rc.apiClient.Watch(ctx, &api.WatchRequest{
		Filter: filter,
	})
	if err != nil {
		return err
	}
	return nil
}
