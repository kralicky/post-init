package relay

import (
	context "context"
	"sync"

	"github.com/kralicky/post-init/pkg/api"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Controller interface {
	PostletConnected(ctx context.Context, an *api.Announcement, client api.InstructionClient)
	ClientConnected(ctx context.Context, clientKey ssh.PublicKey)
	Watch(ctx context.Context, clientKey ssh.PublicKey, req *api.WatchRequest) (<-chan *api.Announcement, error)
	Lookup(ctx context.Context, fingerprint string) (api.InstructionClient, error)
}

type activePostlet struct {
	client       api.InstructionClient
	announcement *api.Announcement
}

type activeWatch struct {
	ch  chan *api.Announcement
	req *api.WatchRequest
}

type controller struct {
	mu             sync.Mutex
	activePostlets map[string]activePostlet
	activeClients  map[string]ssh.PublicKey
	activeWatches  map[string]activeWatch
}

func NewController() Controller {
	return &controller{
		activePostlets: make(map[string]activePostlet),
	}
}

func (c *controller) PostletConnected(ctx context.Context, an *api.Announcement, client api.InstructionClient) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fp, _ := an.Fingerprint() // error already checked in Announce
	c.activePostlets[fp] = activePostlet{
		client:       client,
		announcement: an,
	}
	for _, authorizedKey := range an.AuthorizedKeys {
		if watch, ok := c.activeWatches[authorizedKey.Fingerprint]; ok {
			if an.FilterAccepts(watch.req.Filter) {
				watch.ch <- an
			}
		}
	}
	go func() {
		<-ctx.Done()
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.activePostlets, fp)
	}()
}

func (c *controller) ClientConnected(ctx context.Context, clientKey ssh.PublicKey) {
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
	for _, v := range c.activePostlets {
		if v.announcement.FilterAccepts(req.Filter) {
			ch <- v.announcement
		}
	}
	return ch, nil
}

func (c *controller) Lookup(ctx context.Context, fingerprint string) (api.InstructionClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if an, ok := c.activePostlets[fingerprint]; ok {
		return an.client, nil
	}
	return nil, status.Error(codes.NotFound, "not found")
}
