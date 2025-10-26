
# @eliza-dot-aes/common

Core encryption and decryption functionality for the eliza-dot-aes library.

## Features

- Support customizable cryptographic backends through callback functions
- AES-CBC encryption with HMAC-SHA512
- Secure message padding and random prefix generation
- TypeScript support with full type definitions

## Installation

```bash
pnpm add @eliza-dot-aes/common
```

## Usage

### SR25519 Example

```typescript
import { CryptMessage } from '@eliza-dot-aes/common';
import * as sr25519 from '@scure/sr25519';

// Initialize CryptMessage with SR25519
const alice = await CryptMessage.build(
    "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5e", // seed
    "sr25519",
    // Shared secret callback
    async (privateKey: Uint8Array, publicKey: Uint8Array) => {
        return sr25519.getSharedSecret(privateKey, publicKey);
    },
    // Public/Private key callback
    async (seedOrPrivateKey: Uint8Array) => {
        const privateKey = sr25519.secretFromSeed(seedOrPrivateKey);
        const publicKey = sr25519.getPublicKey(privateKey);
        return [publicKey, privateKey];
    }
);

const bob = await CryptMessage.build(
    "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c50", // different seed
    "sr25519",
    async (privateKey: Uint8Array, publicKey: Uint8Array) => {
        return sr25519.getSharedSecret(privateKey, publicKey);
    },
    async (seedOrPrivateKey: Uint8Array) => {
        const privateKey = sr25519.secretFromSeed(seedOrPrivateKey);
        const publicKey = sr25519.getPublicKey(privateKey);
        return [publicKey, privateKey];
    }
);

// Alice encrypts a message for Bob
const message = "Hello Bob! This is a secret message.";
const encryptedMessage = await alice.encryptMessage(message, bob.publicKey);

// Bob decrypts Alice's message
const decryptedMessage = await bob.decryptMessage(encryptedMessage);
console.log(decryptedMessage); // "Hello Bob! This is a secret message."
```

## API

### CryptMessage

Main class for handling encrypted message operations.

#### Methods

```typescript
// Encrypt a message
async encryptMessage(message: string, toPublicKey: Uint8Array): Promise<string>

// Decrypt a message
async decryptMessage(message: string): Promise<string>
```

## Security

- Uses AES-256-CBC for encryption
- Implements HMAC-SHA512 for message authentication
- Includes random padding for message length obfuscation
- Supports different cryptographic backends for key exchange

## License

Apache License 2.0