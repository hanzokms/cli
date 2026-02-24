/*
Copyright (c) 2024 Hanzo AI Inc.
*/
package main

import (
	"os"

	"github.com/hanzokms/cli/packages/cmd"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(cmd.GetLoggerConfig(os.Stderr))
	cmd.Execute()
}
