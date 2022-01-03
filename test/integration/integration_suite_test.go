package integration

import (
	"testing"

	"github.com/kralicky/post-init/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var testEnv *test.Environment

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	env, err := test.NewEnvironment()
	Expect(err).To(BeNil())
	testEnv = env
})

var _ = AfterSuite(func() {
	testEnv.Destroy()
})
