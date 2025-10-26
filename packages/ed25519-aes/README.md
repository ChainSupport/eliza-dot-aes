# @eliza-dot-aes/ed25519-aes

AES encryption implementation using Ed25519/X25519 for key exchange.

## Features

- Ed25519 key generation with X25519 key exchange
- AES-CBC encryption with HMAC-SHA512
- Secure message padding and random prefix generation
- TypeScript support with full type definitions

## Installation

```bash
pnpm add @eliza-dot-aes/ed25519-aes
```

## Usage

Here's a complete example showing how to encrypt and decrypt messages between two parties:

```typescript
import { ED25519AES } from '@eliza-dot-aes/ed25519-aes';

async function main() {
    // Initialize Alice and Bob with their private keys
    const alice = await ED25519AES.build(
        "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5e"
    );
    const bob = await ED25519AES.build(
        "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5d"
    );

    // Wait for initialization (key generation)
    // await new Promise(resolve => setTimeout(resolve, 100));

    // Alice encrypts a message for Bob
    const message = "Hello Bob! This is a secret message from Alice.";
    const encryptedMessage = await alice.encryptMessage(message, bob.publicKey);
    console.log("Encrypted:", encryptedMessage);

    // Bob decrypts Alice's message
    const decryptedMessage = await bob.decryptMessage(encryptedMessage);
    console.log("Decrypted:", decryptedMessage);

    // Bob sends a reply to Alice
    const reply = "Hi Alice! Got your message, here's my secret reply.";
    const encryptedReply = await bob.encryptMessage(reply, alice.publicKey);
    console.log("Encrypted Reply:", encryptedReply);

    // Alice decrypts Bob's reply
    const decryptedReply = await alice.decryptMessage(encryptedReply);
    console.log("Decrypted Reply:", decryptedReply);
}

main().catch(console.error);
```

## API

### ED25519AES

Main class for handling encrypted message operations.

#### Constructor

```typescript
constructor(seedOrprivateKey: string)
```

- `seedOrprivateKey`: Hexadecimal string of seed for Ed25519 key generation

#### Methods

```typescript
// Encrypt a message
async encryptMessage(message: string, toPublicKey: Uint8Array): Promise<string>

// Decrypt a message
async decryptMessage(message: string): Promise<string>
```

## Technical Details

1. Key Generation:
   - Uses Ed25519 for initial key generation
   - Converts Ed25519 keys to X25519 format for Diffie-Hellman
   - Public keys are automatically converted to Montgomery form

2. Key Exchange:
   - Uses X25519 for Diffie-Hellman key exchange
   - Automatically handles conversion between Ed25519 and X25519 formats
   - Generates shared secrets using Montgomery ladder

## Security Features

- Uses Ed25519/X25519 for secure key exchange
- AES-256-CBC for symmetric encryption
- HMAC-SHA512 for message authentication
- Random padding for message length obfuscation
- Secure key derivation from shared secrets
- Automatic key format conversion

## License

Apache License 2.0
