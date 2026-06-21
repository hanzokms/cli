package util

import (
	"fmt"
	"os"
	"os/exec"

	kmsSdk "github.com/infisical/go-sdk"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type AuthStrategyType string

var AuthStrategy = struct {
	UNIVERSAL_AUTH    AuthStrategyType
	KUBERNETES_AUTH   AuthStrategyType
	AZURE_AUTH        AuthStrategyType
	GCP_ID_TOKEN_AUTH AuthStrategyType
	GCP_IAM_AUTH      AuthStrategyType
	AWS_IAM_AUTH      AuthStrategyType
	OIDC_AUTH         AuthStrategyType
	JWT_AUTH          AuthStrategyType
	LDAP_AUTH         AuthStrategyType
}{
	UNIVERSAL_AUTH:    "universal-auth",
	KUBERNETES_AUTH:   "kubernetes",
	AZURE_AUTH:        "azure",
	GCP_ID_TOKEN_AUTH: "gcp-id-token",
	GCP_IAM_AUTH:      "gcp-iam",
	AWS_IAM_AUTH:      "aws-iam",
	OIDC_AUTH:         "oidc-auth",
	JWT_AUTH:          "jwt-auth",
	LDAP_AUTH:         "ldap-auth",
}

var AVAILABLE_AUTH_STRATEGIES = []AuthStrategyType{
	AuthStrategy.UNIVERSAL_AUTH,
	AuthStrategy.KUBERNETES_AUTH,
	AuthStrategy.AZURE_AUTH,
	AuthStrategy.GCP_ID_TOKEN_AUTH,
	AuthStrategy.GCP_IAM_AUTH,
	AuthStrategy.AWS_IAM_AUTH,
	AuthStrategy.OIDC_AUTH,
	AuthStrategy.JWT_AUTH,
	AuthStrategy.LDAP_AUTH,
}

func IsAuthMethodValid(authMethod string, allowUserAuth bool) (isValid bool, strategy AuthStrategyType) {

	if authMethod == "user" && allowUserAuth {
		return true, ""
	}

	for _, strategy := range AVAILABLE_AUTH_STRATEGIES {
		if string(strategy) == authMethod {
			return true, strategy
		}
	}
	return false, ""
}

// EstablishUserLoginSession handles the login flow to either create a new session or restore an expired one.
// It returns fresh user details if login is successful.
func EstablishUserLoginSession() LoggedInUserDetails {
	log.Info().Msg("No valid login session found, triggering login flow")

	exePath, err := os.Executable()
	if err != nil {
		PrintErrorMessageAndExit(fmt.Sprintf("Failed to determine executable path: %v", err))
	}

	// Spawn kms login command
	loginCmd := exec.Command(exePath, "login", "--silent")
	loginCmd.Stdin = os.Stdin
	loginCmd.Stdout = os.Stdout
	loginCmd.Stderr = os.Stderr

	err = loginCmd.Run()
	if err != nil {
		PrintErrorMessageAndExit(fmt.Sprintf("Failed to automatically trigger login flow. Please run [kms login] manually to login."))
	}

	loggedInUserDetails, err := GetCurrentLoggedInUserDetails(true)
	if err != nil {
		PrintErrorMessageAndExit("You must be logged in to run this command. To login, run [kms login]")
	}

	if loggedInUserDetails.LoginExpired {
		PrintErrorMessageAndExit("Your login session has expired. Please run [kms login]")
	}

	return loggedInUserDetails
}

type SdkAuthenticator struct {
	kmsClient kmsSdk.InfisicalClientInterface
	cmd             *cobra.Command
}

func NewSdkAuthenticator(kmsClient kmsSdk.InfisicalClientInterface, cmd *cobra.Command) *SdkAuthenticator {
	return &SdkAuthenticator{
		kmsClient: kmsClient,
		cmd:             cmd,
	}
}
func (a *SdkAuthenticator) HandleUniversalAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	clientId, err := GetCmdFlagOrEnv(a.cmd, "client-id", []string{KMS_UNIVERSAL_AUTH_CLIENT_ID_NAME})

	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	clientSecret, err := GetCmdFlagOrEnv(a.cmd, "client-secret", []string{KMS_UNIVERSAL_AUTH_CLIENT_SECRET_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	// We are not providing an environment variable because kms go sdk will check for the environment variable when value is emtpy
	// Refer: https://github.com/Infisical/go-sdk/blob/main/packages/util/constants.go#L10
	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).UniversalAuthLogin(clientId, clientSecret)
}

func (a *SdkAuthenticator) HandleJwtAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	jwt, err := GetCmdFlagOrEnv(a.cmd, "jwt", []string{KMS_JWT_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).JwtAuthLogin(identityId, jwt)
}

func (a *SdkAuthenticator) HandleKubernetesAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	serviceAccountTokenPath, err := GetCmdFlagOrEnv(a.cmd, "service-account-token-path", []string{KMS_KUBERNETES_SERVICE_ACCOUNT_TOKEN_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).KubernetesAuthLogin(identityId, serviceAccountTokenPath)
}

func (a *SdkAuthenticator) HandleAzureAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).AzureAuthLogin(identityId, "")
}

func (a *SdkAuthenticator) HandleGcpIdTokenAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).GcpIdTokenAuthLogin(identityId)
}

func (a *SdkAuthenticator) HandleGcpIamAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	serviceAccountKeyFilePath, err := GetCmdFlagOrEnv(a.cmd, "service-account-key-file-path", []string{KMS_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).GcpIamAuthLogin(identityId, serviceAccountKeyFilePath)
}

func (a *SdkAuthenticator) HandleAwsIamAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).AwsIamAuthLogin(identityId)
}

func (a *SdkAuthenticator) HandleOidcAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	jwt, err := GetCmdFlagOrEnv(a.cmd, "jwt", []string{KMS_JWT_NAME, KMS_OIDC_AUTH_JWT_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).OidcAuthLogin(identityId, jwt)
}

func (a *SdkAuthenticator) HandleLdapAuthLogin() (credential kmsSdk.MachineIdentityCredential, e error) {
	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{KMS_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	ldapUsername, err := GetCmdFlagOrEnv(a.cmd, "ldap-username", []string{KMS_LDAP_USERNAME})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	ldapPassword, err := GetCmdFlagOrEnv(a.cmd, "ldap-password", []string{KMS_LDAP_PASSWORD})
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return kmsSdk.MachineIdentityCredential{}, err
	}

	return a.kmsClient.Auth().WithOrganizationSlug(organizationSlug).LdapAuthLogin(identityId, ldapUsername, ldapPassword)
}
