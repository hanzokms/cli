package relay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	gatewayv2 "github.com/hanzokms/cli/packages/gateway-v2"
	"github.com/hanzokms/cli/packages/util"
	"github.com/rs/zerolog/log"
)

// InstallRelaySystemdService installs the systemd unit and writes configuration for the relay.
// token is used for org-type relays (written as KMS_TOKEN). For instance-type relays,
// relayAuthSecret is written as KMS_RELAY_AUTH_SECRET.
func InstallRelaySystemdService(token string, domain string, name string, host string, instanceType string, relayAuthSecret string, serviceLogFile string) error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return nil
	}

	configDir := "/etc/kms"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Build config content
	// Relay identity/name and network settings
	configContent := fmt.Sprintf("%s=%s\n%s=%s\n%s=%s\n",
		gatewayv2.RELAY_NAME_ENV_NAME, name,
		gatewayv2.RELAY_HOST_ENV_NAME, host,
		gatewayv2.RELAY_TYPE_ENV_NAME, instanceType)

	// API URL for self-hosted
	if domain != "" {
		configContent += fmt.Sprintf("KMS_API_URL=%s\n", domain)
	}

	// Auth settings
	if instanceType == "instance" {
		if relayAuthSecret != "" {
			configContent += fmt.Sprintf("%s=%s\n", gatewayv2.RELAY_AUTH_SECRET_ENV_NAME, relayAuthSecret)
		}
	} else {
		if token != "" {
			configContent += fmt.Sprintf("KMS_TOKEN=%s\n", token)
		}
	}

	environmentFilePath := filepath.Join(configDir, "relay.conf")
	if err := os.WriteFile(environmentFilePath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write environment file: %v", err)
	}

	serviceName := "kms-relay"

	if err := util.WriteSystemdServiceFile(serviceLogFile, environmentFilePath, serviceName, "relay", "Hanzo KMS Relay Service"); err != nil {
		return fmt.Errorf("failed to write systemd service file: %v", err)
	}

	if err := util.WriteLogrotateFile(serviceLogFile, serviceName); err != nil {
		return fmt.Errorf("failed to write logrotate file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully installed systemd service for Hanzo KMS Relay")
	log.Info().Msg("To start the service, run: sudo systemctl start kms-relay")
	log.Info().Msg("To enable the service on boot, run: sudo systemctl enable kms-relay")

	return nil
}

func UninstallRelaySystemdService() error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	// Stop the service if it's running
	stopCmd := exec.Command("systemctl", "stop", "kms-relay")
	if err := stopCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to stop service: %v", err)
	}

	// Disable the service
	disableCmd := exec.Command("systemctl", "disable", "kms-relay")
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	// Remove the service file
	servicePath := "/etc/systemd/system/kms-relay.service"
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	// Remove the configuration file
	configPath := "/etc/kms/relay.conf"
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %v", err)
	}

	// Reload systemd to apply changes
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully uninstalled Hanzo KMS Relay systemd service")
	return nil
}
