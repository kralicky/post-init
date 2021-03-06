package commands

import (
	"context"
	"time"

	"github.com/kralicky/post-init/pkg/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func BuildAgentCmd() *cobra.Command {
	var relayAddress string
	var relayCert string
	var insecure bool
	var timeout int

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the agent and connect to a relay",
		Run: func(cmd *cobra.Command, args []string) {
			d := agent.New(
				agent.WithInsecure(insecure),
				agent.WithRelayAddress(relayAddress),
				agent.WithRelayCACert(relayCert),
				agent.WithTimeout(time.Duration(timeout)*time.Second),
			)
			if err := d.Start(context.Background()); err != nil {
				logrus.Error(err)
			}
		},
	}
	cmd.Flags().StringVar(&relayAddress, "relay-address", "", "Address of the relay to connect to")
	cmd.Flags().StringVar(&relayCert, "cacert", "", "(optional) path to a self-signed certificate for the relay")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Run the agent in insecure mode (for testing only)")
	cmd.Flags().IntVar(&timeout, "timeout", 60, "duration in seconds to wait for instructions from the relay before exiting")
	return cmd
}
