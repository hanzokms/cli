package telemetry

import (
	"github.com/hanzokms/cli/packages/util"
	"github.com/denisbrodbeck/machineid"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
)

var INSIGHTS_API_KEY_FOR_CLI string

type Telemetry struct {
	isEnabled     bool
	insightsClient posthog.Client
}

type NoOpLogger struct{}

func (NoOpLogger) Logf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func (NoOpLogger) Errorf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func NewTelemetry(telemetryIsEnabled bool) *Telemetry {
	if INSIGHTS_API_KEY_FOR_CLI != "" {
		client, _ := posthog.NewWithConfig(
			INSIGHTS_API_KEY_FOR_CLI,
			posthog.Config{
				Logger: NoOpLogger{},
			},
		)

		return &Telemetry{isEnabled: telemetryIsEnabled, insightsClient: client}
	} else {
		return &Telemetry{isEnabled: false}
	}
}

func (t *Telemetry) CaptureEvent(eventName string, properties posthog.Properties) {
	userIdentity, err := t.GetDistinctId()
	if err != nil {
		return
	}

	if t.isEnabled {
		t.insightsClient.Enqueue(posthog.Capture{
			DistinctId: userIdentity,
			Event:      eventName,
			Properties: properties,
		})

		defer t.insightsClient.Close()
	}
}

func (t *Telemetry) GetDistinctId() (string, error) {
	var distinctId string
	var outputErr error

	machineId, err := machineid.ID()
	if err != nil {
		outputErr = err
	}

	infisicalConfig, err := util.GetConfigFile()
	if err != nil {
		outputErr = err
	}

	if infisicalConfig.LoggedInUserEmail != "" {
		distinctId = infisicalConfig.LoggedInUserEmail
	} else if machineId != "" {
		distinctId = "anonymous_cli_" + machineId
	} else {
		distinctId = ""
	}

	return distinctId, outputErr
}
