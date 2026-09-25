# Security Policy

## Reporting security-sensitive material

If you notice any accidentally committed credentials, private keys, access tokens, personal data, or other sensitive information, do not repost it in a public issue.

Contact the repository owner privately and identify the affected path/commit.

## Scope

This repository is for preservation, interoperability, and emulator research around discontinued software.

Please do not use project tooling or research to target live third-party services or systems without authorization.

## Secrets

Never commit:

- private keys
- passwords
- API tokens
- session cookies
- account credentials
- personal player/account exports

Use local configuration files excluded by `.gitignore` instead.
