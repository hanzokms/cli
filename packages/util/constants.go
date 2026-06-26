package util

const (
	CONFIG_FILE_NAME                           = "kms-config.json"
	CONFIG_FOLDER_NAME                         = ".kms"
	KMS_DEFAULT_US_URL                   = "https://kms.hanzo.ai"
	KMS_DEFAULT_EU_URL                   = "https://eu.kms.hanzo.ai"
	KMS_WORKSPACE_CONFIG_FILE_NAME       = "kms.json"
	KMS_TOKEN_NAME                       = "KMS_TOKEN"
	KMS_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME = "KMS_UNIVERSAL_AUTH_ACCESS_TOKEN"
	KMS_VAULT_FILE_PASSPHRASE_ENV_NAME   = "KMS_VAULT_FILE_PASSPHRASE" // This works because we've forked the keyring package and added support for this env variable. This explains why you won't find any occurrences of it in the CLI codebase.

	KMS_BOOTSTRAP_EMAIL_NAME        = "KMS_ADMIN_EMAIL"
	KMS_BOOTSTRAP_PASSWORD_NAME     = "KMS_ADMIN_PASSWORD"
	KMS_BOOTSTRAP_ORGANIZATION_NAME = "KMS_ADMIN_ORGANIZATION"

	// agent retry config
	KMS_RETRY_BASE_DELAY_NAME  = "KMS_RETRY_BASE_DELAY"
	KMS_RETRY_MAX_DELAY_NAME   = "KMS_RETRY_MAX_DELAY"
	KMS_RETRY_MAX_RETRIES_NAME = "KMS_RETRY_MAX_RETRIES"

	VAULT_BACKEND_AUTO_MODE = "auto"
	VAULT_BACKEND_FILE_MODE = "file"

	KMS_AUTH_METHOD_NAME = "KMS_AUTH_METHOD"

	// Universal Auth
	KMS_UNIVERSAL_AUTH_CLIENT_ID_NAME     = "KMS_UNIVERSAL_AUTH_CLIENT_ID"
	KMS_UNIVERSAL_AUTH_CLIENT_SECRET_NAME = "KMS_UNIVERSAL_AUTH_CLIENT_SECRET"

	// Kubernetes auth
	KMS_KUBERNETES_SERVICE_ACCOUNT_TOKEN_NAME = "KMS_KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH"

	// GCP Auth
	KMS_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH_NAME = "KMS_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH"

	// OIDC Auth
	KMS_OIDC_AUTH_JWT_NAME = "KMS_OIDC_AUTH_JWT" // deprecated in favor of KMS_JWT

	// JWT AUTH
	KMS_JWT_NAME = "KMS_JWT"
	// LDAP AUTH
	KMS_LDAP_USERNAME   = "KMS_LDAP_USERNAME"
	KMS_LDAP_PASSWORD   = "KMS_LDAP_PASSWORD"
	KMS_ORGANIZATION_ID = "KMS_ORGANIZATION_ID"

	KMS_GATEWAY_TOKEN_NAME_LEGACY = "TOKEN" // backwards compatibility with gateway helm chart, where token was the only supported auth method

	// Generic env variable used for auth methods that require a machine identity ID
	KMS_MACHINE_IDENTITY_ID_NAME = "KMS_MACHINE_IDENTITY_ID"

	SECRET_TYPE_PERSONAL      = "personal"
	SECRET_TYPE_SHARED        = "shared"
	KEYRING_SERVICE_NAME      = "hanzo-kms"
	PERSONAL_SECRET_TYPE_NAME = "personal"
	SHARED_SECRET_TYPE_NAME   = "shared"

	SERVICE_TOKEN_IDENTIFIER        = "service-token"
	UNIVERSAL_AUTH_TOKEN_IDENTIFIER = "universal-auth-token"

	KMS_BACKUP_SECRET                = "kms-backup-secrets"
	KMS_BACKUP_SECRET_ENCRYPTION_KEY = "kms-backup-secret-encryption-key"

	KUBERNETES_SERVICE_HOST_ENV_NAME        = "KUBERNETES_SERVICE_HOST"
	KUBERNETES_SERVICE_PORT_HTTPS_ENV_NAME  = "KUBERNETES_SERVICE_PORT_HTTPS"
	KUBERNETES_SERVICE_ACCOUNT_CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

var (
	CLI_VERSION = "devel"
)
