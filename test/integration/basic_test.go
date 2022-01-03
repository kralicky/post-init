package integration

import (
	"context"
	"time"

	"github.com/kralicky/post-init/pkg/api"
	"github.com/kralicky/post-init/pkg/sdk"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("Basic Integration", func() {
	signer := testEnv.NewEd25519Keypair()

	Specify("setup relay", func() {
		testEnv.SpawnRelay()
	})
	Specify("setup daemon", func() {
		testEnv.SpawnDaemon(signer.PublicKey())
	})
	Specify("setup client", func() {
		c := testEnv.NewClient(signer)
		clientCtx, ca := context.WithTimeout(context.Background(), 30*time.Second)
		defer ca()
		Expect(c.Connect(clientCtx)).To(Succeed())
		done := make(chan struct{})
		err := c.Notify(clientCtx, &api.BasicFilter{
			Operator:         api.Operator_Or,
			HasAuthorizedKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		}, func(cc *sdk.ControlContext) {
			output, err := cc.RunCommand(&api.Command{
				Command: "echo",
				Args:    []string{"hello", "world"},
			})
			Expect(err).To(BeNil())
			Expect(output.Stdout).To(Equal("hello world\n"))
			close(done)
		})
		Eventually(done).Should(BeClosed())
		Expect(err).To(BeNil())
	})
})
