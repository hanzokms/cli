/*
Copyright (c) 2024 Hanzo AI Inc.
*/
package cmd

import (
	"os"

	"github.com/hanzokms/cli/packages/util"
	insights "github.com/hanzoai/insights-go"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:                   "reset",
	Short:                 "Used to delete all Hanzo KMS related data on your machine",
	DisableFlagsInUseLine: true,
	Example:               "kms reset",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// delete keyring item of current logged in user
		configFile, _ := util.GetConfigFile()

		// delete from keyring
		util.DeleteValueInKeyring(configFile.LoggedInUserEmail)

		// delete config
		_, pathToDir, err := util.GetFullConfigFilePath()
		if err != nil {
			util.HandleError(err)
		}

		os.RemoveAll(pathToDir)

		// delete secrets backup
		util.DeleteBackupSecrets()

		util.PrintSuccessMessage("Reset successful")
		Telemetry.CaptureEvent("cli-command:reset", insights.NewProperties().Set("version", util.CLI_VERSION))
	},
}

func init() {
	RootCmd.AddCommand(resetCmd)
}
