package relay

import (
	context "context"
	"sync"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Controller interface {
	AgentConnected(ctx context.Context, an *api.Announcement, client api.InstructionClient)
	ClientConnected(ctx context.Context, clientKey ssh.PublicKey)
	Watch(ctx context.Context, clientKey ssh.PublicKey, req *api.WatchRequest) (<-chan *api.Announcement, error)
	Lookup(ctx context.Context, fingerprint string) (api.InstructionClient, error)
}

type activeAgent struct {
	client       api.InstructionClient
	announcement *api.Announcement
}

type activeWatch struct {
	ch  chan *api.Announcement
	req *api.WatchRequest
}

type controller struct {
	mu            sync.Mutex
	activeAgents  map[string]activeAgent
	activeClients map[string]ssh.PublicKey
	activeWatches map[string]activeWatch
}

func NewController() Controller {
	return &controller{
		activeAgents:  make(map[string]activeAgent),
		activeClients: make(map[string]ssh.PublicKey),
		activeWatches: make(map[string]activeWatch),
	}
}

func (c *controller) AgentConnected(ctx context.Context, an *api.Announcement, client api.InstructionClient) {
	logrus.Info("Agent connected: " + string(an.PreferredHostPublicKey))
	c.mu.Lock()
	defer c.mu.Unlock()
	fp, _ := an.Fingerprint() // error already checked in Announce
	c.activeAgents[fp] = activeAgent{
		client:       client,
		announcement: an,
	}
	for _, authorizedKey := range an.AuthorizedKeys {
		if watch, ok := c.activeWatches[authorizedKey.Fingerprint]; ok {
			if an.FilterAccepts(watch.req.Filter) {
				logrus.Info("Handling late-join")
				watch.ch <- an
			} else {
				logrus.Info("Filtered out late-join")
			}
		}
	}
	go func() {
		<-ctx.Done()
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.activeAgents, fp)
	}()
}

func (c *controller) ClientConnected(ctx context.Context, clientKey ssh.PublicKey) {
	logrus.Info("Client connected")
	c.mu.Lock()
	defer c.mu.Unlock()
	fp := ssh.FingerprintSHA256(clientKey)
	c.activeClients[fp] = clientKey
	go func() {
		<-ctx.Done()
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.activeWatches, fp)
		delete(c.activeClients, fp)
	}()
}

func (c *controller) Watch(ctx context.Context, clientKey ssh.PublicKey, req *api.WatchRequest) (<-chan *api.Announcement, error) {
	logrus.Info("Watch requested by client")
	c.mu.Lock()
	defer c.mu.Unlock()
	fp := ssh.FingerprintSHA256(clientKey)
	if _, ok := c.activeClients[fp]; !ok {
		return nil, status.Error(codes.PermissionDenied, "key is not authorized")
	}
	if _, ok := c.activeWatches[fp]; ok {
		return nil, status.Error(codes.AlreadyExists, "already watching")
	}
	ch := make(chan *api.Announcement, 256)
	c.activeWatches[fp] = activeWatch{
		ch:  ch,
		req: req,
	}
	// late join; all other notifications happen upon receiving announcements
	for _, v := range c.activeAgents {
		if v.announcement.FilterAccepts(req.Filter) {
			logrus.Info("Handling late-join")
			ch <- v.announcement
		}
	}
	return ch, nil
}

func (c *controller) Lookup(ctx context.Context, fingerprint string) (api.InstructionClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if an, ok := c.activeAgents[fingerprint]; ok {
		return an.client, nil
	}
	return nil, status.Error(codes.NotFound, "not found")
}
