package main

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "gks",
	Short: "Manage cryptographic keystores",
	RunE: func(cmd *cobra.Command, args []string) error {
		// If no sub command is given, use serve as default
		return cmd.Help()
	},
}
