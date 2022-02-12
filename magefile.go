//go:build mage

package main

import (
	"github.com/magefile/mage/mg"

	// mage:import
	"github.com/kralicky/spellbook/build"
	// mage:import
	"github.com/kralicky/spellbook/mockgen"
	// mage:import
	_ "github.com/kralicky/spellbook/test/ginkgo"
	// mage:import
	protobuf "github.com/kralicky/spellbook/protobuf/ragu"
)

var Default = All

func All() {
	mg.Deps(build.Build)
}

func Generate() {
	mg.Deps(mockgen.Mockgen, protobuf.Protobuf)
}

func init() {
	build.Deps(Generate)

	protobuf.Config.Protos = []protobuf.Proto{
		{
			Source:  "pkg/api/relay.proto",
			DestDir: "pkg/api",
		},
		{
			Source:  "pkg/api/agent_api.proto",
			DestDir: "pkg/api",
		},
		{
			Source:  "pkg/api/client_api.proto",
			DestDir: "pkg/api",
		},
		{
			Source:  "pkg/api/announce.proto",
			DestDir: "pkg/api",
		},
		{
			Source:  "pkg/api/instructions.proto",
			DestDir: "pkg/api",
		},
	}
	mockgen.Config.Mocks = []mockgen.Mock{
		{
			Source: "pkg/api/agent_api_grpc.pb.go",
			Dest:   "pkg/test/mock/api/mock_agent_api_grpc.go",
			Types:  []string{"InstructionClient"},
		},
	}
}
