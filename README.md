# Hanzo KMS CLI

The official **Hanzo KMS CLI** for secret management. Inject secrets into applications and manage your Hanzo KMS infrastructure.

## Features

- **Inject secrets** into applications and development workflows
- **Scan for secret leaks** in your codebase and git history
- **Export secrets** to various formats (dotenv, JSON, YAML)
- **Authenticate** with Hanzo KMS Cloud or self-hosted instances
- **Integrate** with CI/CD pipelines and Docker containers

## Installation

### Package Managers

**macOS**

```bash
brew install hanzokms/tap/kms
```

**NPM**

```bash
npm install -g @hanzokms/cli
```

### Direct Download

Download binaries from [GitHub Releases](https://github.com/hanzokms/cli/releases).

## Quick Start

```bash
# Login to your Hanzo KMS instance
kms login

# Initialize a project
kms init

# Inject secrets into a process
kms run -- your-command

# Export secrets
kms export --format=dotenv
```

## Development

```bash
git clone https://github.com/hanzokms/cli.git
cd cli
go build -o kms .
go test ./...
```

## Documentation

See [kms.hanzo.ai/docs](https://kms.hanzo.ai/docs) for full documentation.

## License

MIT License. Copyright (c) 2024 Hanzo AI Inc.
