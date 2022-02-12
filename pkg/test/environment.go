package test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kralicky/post-init/pkg/agent"
	"github.com/kralicky/post-init/pkg/relay"
	"github.com/kralicky/post-init/pkg/sdk"
	"github.com/mholt/archiver/v3"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/phayes/freeport"
	"golang.org/x/crypto/ssh"
)

type certs struct {
	CACert           string
	CAKey            string
	IntermediateCert string
	IntermediateKey  string
	CertBundle       string
	Key              string
}

type Environment struct {
	Context   context.Context
	Certs     certs
	TempDir   string
	RelayAddr string
}

var stepDownloadUrl = `https://dl.step.sm/gh-release/cli/gh-release-header/v0.18.0/step_linux_0.18.0_amd64.tar.gz`

func NewEnvironment() (*Environment, error) {
	tempDir, err := os.MkdirTemp("", "post-init-test")
	if err != nil {
		return nil, err
	}
	fmt.Println("Created temp dir:", tempDir)

	// find top level dir containing go.mod
	topLevel, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	fmt.Println("Current dir:", topLevel)
	for {
		if _, err := os.Stat(filepath.Join(topLevel, "go.mod")); err == nil {
			break
		}
		topLevel = filepath.Dir(topLevel)
	}
	fmt.Println("Top level dir:", topLevel)
	// create testbin
	testbin := filepath.Join(topLevel, "testbin")
	if err := os.Mkdir(testbin, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	// download step if it doesn't exist in testbin
	if _, err := os.Stat(filepath.Join(testbin, "step")); err != nil {
		fmt.Println("Downloading step cli to testbin/step")
		resp, err := http.Get(stepDownloadUrl)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		tgz := archiver.NewTarGz()
		if err := tgz.Open(bytes.NewReader(data), 0); err != nil {
			return nil, err
		}
		defer tgz.Close()
		for {
			f, err := tgz.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if f.Name() == "step" {
				data, err := io.ReadAll(f)
				if err != nil {
					return nil, err
				}
				if err := os.WriteFile(filepath.Join(testbin, "step"), data, 0755); err != nil {
					return nil, err
				}
			}
		}
	}

	stepCLI := filepath.Join(testbin, "step")
	cmd := exec.Command(stepCLI, "certificate", "create", "Test CA",
		"root_ca.crt", "root_ca.key", "--profile=root-ca",
		"--insecure", "--no-password")
	cmd.Dir = tempDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create test CA: %s", out)
	}
	cmd = exec.Command(stepCLI, "certificate", "create", "Test Intermediate",
		"intermediate_ca.crt", "intermediate_ca.key", "--profile=intermediate-ca",
		"--insecure", "--no-password", "--ca=root_ca.crt", "--ca-key=root_ca.key")
	cmd.Dir = tempDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create test intermediate CA: %s", out)
	}
	cmd = exec.Command(stepCLI, "certificate", "create", "test",
		"test.crt", "test.key",
		"--profile=leaf", "--ca=intermediate_ca.crt", "--ca-key=intermediate_ca.key",
		"--san=127.0.0.1",
		"--bundle", "--insecure", "--no-password")
	cmd.Dir = tempDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create test cert: %s", out)
	}

	return &Environment{
		Context: context.Background(),
		TempDir: tempDir,
		Certs: certs{
			CACert:           filepath.Join(tempDir, "root_ca.crt"),
			CAKey:            filepath.Join(tempDir, "root_ca.key"),
			IntermediateCert: filepath.Join(tempDir, "intermediate_ca.crt"),
			IntermediateKey:  filepath.Join(tempDir, "intermediate_ca.key"),
			CertBundle:       filepath.Join(tempDir, "test.crt"),
			Key:              filepath.Join(tempDir, "test.key"),
		},
	}, nil
}

func (e *Environment) SpawnRelay() {
	relayPort, err := freeport.GetFreePort()
	Expect(err).NotTo(HaveOccurred())
	e.RelayAddr = fmt.Sprintf("127.0.0.1:%d", relayPort)
	r := relay.NewRelayServer(
		relay.Insecure(false),
		relay.ListenAddress(e.RelayAddr),
		relay.ServingCerts(e.Certs.CertBundle, e.Certs.Key),
	)
	go func() {
		defer GinkgoRecover()
		ctx, ca := context.WithCancel(e.Context)
		defer ca()
		if err := r.Serve(ctx); err != nil {
			panic(err)
		}
	}()
}

func (e *Environment) SpawnAgent(authorizedKeys ...ssh.PublicKey) {
	a := agent.New(
		agent.WithInsecure(false),
		agent.WithRelayAddress(e.RelayAddr),
		agent.WithRelayCACert(e.Certs.CACert),
		agent.WithTimeout(2*time.Second),
		agent.WithExtraAuthorizedKeys(func() []string {
			var keys []string
			for _, k := range authorizedKeys {
				keys = append(keys, string(ssh.MarshalAuthorizedKey(k)))
			}
			return keys
		}()...),
	)
	go func() {
		defer GinkgoRecover()
		ctx, ca := context.WithCancel(e.Context)
		defer ca()
		if err := a.Start(ctx); err != nil {
			panic(err)
		}
	}()
}

func (e *Environment) NewRSAKeypair() ssh.Signer {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	signer, err := ssh.NewSignerFromKey(priv)
	Expect(err).NotTo(HaveOccurred())
	return signer
}

func (e *Environment) NewEd25519Keypair() ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	signer, err := ssh.NewSignerFromKey(priv)
	Expect(err).NotTo(HaveOccurred())
	return signer
}

func (e *Environment) NewClient(signer ssh.Signer) *sdk.RelayClient {
	c, err := sdk.NewRelayClient(&sdk.ClientConfig{
		Address: e.RelayAddr,
		CACert:  e.Certs.CACert,
		Signer:  signer,
	})
	Expect(err).NotTo(HaveOccurred())
	return c
}

func (e *Environment) Destroy() error {
	if e == nil {
		return nil
	}
	if err := os.RemoveAll(e.TempDir); err != nil {
		return err
	}
	return nil
}
