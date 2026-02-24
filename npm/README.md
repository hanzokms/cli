# @hanzokms/cli

The official Hanzo KMS CLI for secret management, distributed via npm.

## Installation

```bash
npm install -g @hanzokms/cli
```

## Usage

```bash
# Login to your Hanzo KMS instance
kms login

# Initialize a project
kms init

# Inject secrets into a process
kms run -- your-command

# List secrets
kms secrets

# Export secrets
kms export --format=dotenv
```

## Documentation

See [kms.hanzo.ai/docs](https://kms.hanzo.ai/docs) for full documentation.

## License

MIT License. Copyright (c) 2024 Hanzo AI Inc.
