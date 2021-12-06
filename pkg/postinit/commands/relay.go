package commands

import (
	"context"

	"github.com/kralicky/post-init/pkg/relay"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func BuildRelayCmd() *cobra.Command {
	var servingCert string
	var servingKey string
	var insecure bool

	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Run the post-init relay",
		Run: func(cmd *cobra.Command, args []string) {
			srv := relay.NewRelayServer(
				relay.ServingCerts(servingCert, servingKey),
				relay.Insecure(insecure),
			)
			ctx := context.Background()
			logrus.Info("Starting post-init relay")
			if err := srv.Serve(ctx); err != nil {
				logrus.Error(err)
			}
		},
	}
	cmd.Flags().StringVar(&servingCert, "serving-cert", "", "Path to the serving certificate")
	cmd.Flags().StringVar(&servingKey, "serving-key", "", "Path to the serving key")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Run the relay in insecure mode (for testing only)")

	return cmd
}
