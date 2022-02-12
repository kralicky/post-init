package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/golang/mock/gomock"
	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/test/mock/mock_api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("Controller", Ordered, func() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubKey, _ := ssh.NewPublicKey(pub)
	privKey, _ := ssh.NewSignerFromKey(priv)
	_ = privKey
	var mockCtrl *gomock.Controller
	var mockClient *mock_api.MockInstructionClient
	BeforeAll(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		defer mockCtrl.Finish()

		mockClient = mock_api.NewMockInstructionClient(mockCtrl)
		mockClient.EXPECT().
			Command(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, in *api.CommandRequest) (*api.CommandResponse, error) {
				if in.Command.Command != "echo" {
					panic("invalid test")
				}
				return &api.CommandResponse{
					Stdout:   fmt.Sprint(in.Command.Args) + "\n",
					Stderr:   "",
					ExitCode: 0,
				}, nil
			}).
			AnyTimes()
	})

	var c *controller
	When("creating a new controller", func() {
		It("should have no active connections", func() {
			c = NewController().(*controller)
			c.mu.Lock()
			Expect(c.activeAgents).To(BeEmpty())
			Expect(c.activeClients).To(BeEmpty())
			Expect(c.activeWatches).To(BeEmpty())
			c.mu.Unlock()
		})
	})
	var clientCtx context.Context
	var clientCancel context.CancelFunc
	When("a client connects", func() {
		It("should keep track of the active client", func() {
			clientCtx, clientCancel = context.WithCancel(context.Background())
			c.ClientConnected(clientCtx, pubKey)

			c.mu.Lock()
			fp := ssh.FingerprintSHA256(pubKey)
			Expect(c.activeClients).To(HaveKey(fp))
			Expect(c.activeClients[fp]).To(Equal(pubKey))
			c.mu.Unlock()
		})
	})
	var agentCtx context.Context
	var agentCancel context.CancelFunc
	When("an agent connects with the client's authorized key", func() {
		It("should notify the client", func() {
			agentCtx, agentCancel = context.WithCancel(context.Background())
			c.AgentConnected(agentCtx, &api.Announcement{
				AuthorizedKeys: []*api.AuthorizedKey{
					{
						User:        "user",
						Type:        "ssh-ed25519",
						Fingerprint: ssh.FingerprintSHA256(pubKey),
					},
				},
			}, mockClient)
		})
	})
	When("a client disconnects", func() {
		It("should remove the client from the active clients", func() {
			clientCancel()

			Eventually(func() bool {
				c.mu.Lock()
				fp := ssh.FingerprintSHA256(pubKey)
				_, ok := c.activeClients[fp]
				c.mu.Unlock()
				return ok
			}).Should(BeFalse())
		})
	})
	When("an agent disconnects", func() {
		It("should remove the agent from the active agents", func() {
			agentCancel()

			Eventually(func() bool {
				c.mu.Lock()
				fp := ssh.FingerprintSHA256(pubKey)
				_, ok := c.activeAgents[fp]
				c.mu.Unlock()
				return ok
			}).Should(BeFalse())
		})
	})
})
