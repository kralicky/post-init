package sdk

import (
	"context"

	"github.com/kralicky/post-init/pkg/api"
)

type ControlContext interface {
	RunCommand(*api.Command) (*api.CommandResponse, error)
	RunScript(*api.Script) (*api.ScriptResponse, error)
}

type NotifyCallback func(ControlContext)

type controlCtxImpl struct {
	ctx          context.Context
	apiClient    api.ClientAPIClient
	announcement *api.Announcement
}

func (cc *controlCtxImpl) RunCommand(cmd *api.Command) (*api.CommandResponse, error) {
	return cc.apiClient.RunCommand(cc.ctx, &api.CommandRequest{
		Meta: &api.InstructionMeta{
			PeerFingerprint: string(cc.announcement.PreferredHostPublicKey),
		},
		Command: cmd,
	})
}

func (cc *controlCtxImpl) RunScript(sc *api.Script) (*api.ScriptResponse, error) {
	return cc.apiClient.RunScript(cc.ctx, &api.ScriptRequest{
		Meta: &api.InstructionMeta{
			PeerFingerprint: string(cc.announcement.PreferredHostPublicKey),
		},
		Script: sc,
	})
}
