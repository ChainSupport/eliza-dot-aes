
# @eliza-dot-aes/sr25519-aes

AES encryption implementation using SR25519 for key exchange.

## Features

- SR25519-based key exchange
- AES-CBC encryption with HMAC-SHA512
- Secure message padding and random prefix generation
- TypeScript support with full type definitions

## Installation

```bash
pnpm add @eliza-dot-aes/sr25519-aes
```

## Usage

Here's a complete example showing how to encrypt and decrypt messages between two parties:

```typescript
import { SR25519AES } from '@eliza-dot-aes/sr25519-aes';

async function main() {
    // Initialize Alice and Bob with their private keys
    const alice = await SR25519AES.build(
        "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5e"
    );
    const bob = await SR25519AES.build(
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

### SR25519AES

Main class for handling encrypted message operations.

#### Constructor

```typescript
constructor(seedOrprivateKey: string)
```

- `seedOrprivateKey`: Hexadecimal string of seed for SR25519 key generation

#### Methods

```typescript
// Encrypt a message
async encryptMessage(message: string, toPublicKey: Uint8Array): Promise<string>

// Decrypt a message
async decryptMessage(message: string): Promise<string>
```

## Security Features

- Uses SR25519 for secure key exchange
- AES-256-CBC for symmetric encryption
- HMAC-SHA512 for message authentication
- Random padding for message length obfuscation
- Secure key derivation from shared secrets

## License

Apache License 2.0
