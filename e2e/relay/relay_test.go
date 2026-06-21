package relay_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	helpers "github.com/hanzokms/cli/e2e-tests/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelay_RegistersARelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	kms := helpers.NewKMSService().
		WithBackendEnvironment(types.NewMappingWithEquals([]string{
			// This is needed for the private ip (current host) to be accepted for the relay server
			"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		})).
		Up(t, ctx)

	c := kms.ApiClient()
	identity := kms.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity)

	relayName := helpers.RandomSlug(2)
	cmd := helpers.Command{
		Test: t,
		Args: []string{"relay", "start", "--domain", kms.ApiUrl(t)},
		Env: map[string]string{
			"KMS_API_URL":    kms.ApiUrl(t),
			"KMS_RELAY_NAME": relayName,
			"KMS_RELAY_HOST": "host.docker.internal",
			"KMS_TOKEN":      *identity.TokenAuthToken,
		},
	}
	cmd.Start(ctx)
	t.Cleanup(cmd.Stop)

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "Relay server started successfully",
	})
	require.Equal(t, helpers.WaitSuccess, result)

	result = helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &cmd,
		Condition: func() helpers.ConditionResult {
			resp, err := c.GetRelaysWithResponse(ctx)
			if err != nil {
				return helpers.ConditionWait
			}
			if resp.StatusCode() != http.StatusOK {
				return helpers.ConditionWait
			}
			for _, relay := range *resp.JSON200 {
				slog.Info(
					"Relay info",
					"id", relay.Id,
					"name", relay.Name,
					"host", relay.Host,
					"heartbeat", relay.Heartbeat,
				)
				if relay.Name == relayName && relay.Heartbeat != nil {
					slog.Info("Confirmed relay heartbeat")
					return helpers.ConditionSuccess
				}
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, result)

	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "Relay is reachable by KMS",
	})
	assert.Equal(t, helpers.WaitSuccess, result)
}
