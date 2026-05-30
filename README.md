# Walletgen

Educational wallet-generation sandbox.

## Purpose

This repository is for learning about wallet formats, randomness, key handling and local-only experiments. It must not be used to access wallets that belong to other people.

## Safety Rules

- Never paste real seed phrases, private keys or recovery words into test code.
- Never commit secrets, generated private keys or wallet backups.
- Do not use this project to search for or access other people's funds.
- Use offline test data only.
- Treat all generated keys as unsafe unless the code has been reviewed and tested carefully.

## Development Notes

Before running any wallet-related code, inspect it and make sure it does not send data to external services.

Recommended workflow:

```bash
git status
git add .
git commit -m "Describe the change"
```

## Disclaimer

This repository is for educational and lawful use only. Crypto assets can be permanently lost if private keys or seed phrases are mishandled.
