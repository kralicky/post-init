//go:build mage
// +build mage

package main

import (
	"os"
	"path/filepath"

	"github.com/kralicky/ragu/pkg/ragu"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var Default = All

func All() {
	mg.SerialDeps(Generate, Build)
}

func Generate() error {
	files := []string{
		"pkg/api/relay.proto",
		"pkg/api/postlet_api.proto",
		"pkg/api/client_api.proto",
		"pkg/api/announce.proto",
		"pkg/api/instructions.proto",
	}
	for _, f := range files {
		relayProtos, err := ragu.GenerateCode(f, true)
		if err != nil {
			return err
		}
		for _, p := range relayProtos {
			path := filepath.Join("pkg/api", p.GetName())
			if info, err := os.Stat(path); err == nil {
				if info.Mode()&0200 == 0 {
					if err := os.Chmod(path, 0644); err != nil {
						return err
					}
				}
			}
			if err := os.WriteFile(path, []byte(p.GetContent()), 0444); err != nil {
				return err
			}
			if err := os.Chmod(path, 0444); err != nil {
				return err
			}
		}
	}
	return nil
}

func Build() error {
	return sh.RunWithV(map[string]string{
		"CGO_ENABLED": "0",
	}, mg.GoCmd(), "build", "-ldflags", `-w -s`, "-o", "./bin/post-init", "./cmd/post-init")
}
