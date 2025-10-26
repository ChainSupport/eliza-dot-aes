
# Eliza-dot-AES

AES encryption implementation with multiple cryptographic backends.

## Packages

This monorepo contains the following packages:

- [@eliza-dot-aes/common](./packages/common) - Common utilities and interfaces for all packages
- [@eliza-dot-aes/sr25519-aes](./packages/sr25519-aes) - AES encryption with SR25519 cryptographic backend
- [@eliza-dot-aes/ed25519-aes](./packages/ed25519-aes) - AES encryption with ED25519 cryptographic backend
- [@eliza-dot-aes/ecdsa-aes](./packages/ecdsa-aes) - AES encryption with ECDSA cryptographic backend

## Development

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test:coverage
```

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.