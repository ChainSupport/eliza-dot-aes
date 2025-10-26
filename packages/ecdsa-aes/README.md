# @eliza-dot-aes/ecdsa-aes

AES encryption implementation using secp256k1 ECDSA for key exchange.

## Features

- secp256k1 ECDSA key generation and exchange
- AES-CBC encryption with HMAC-SHA512
- Secure message padding and random prefix generation
- TypeScript support with full type definitions
- Compatible with Ethereum private keys

## Installation

```bash
pnpm add @eliza-dot-aes/ecdsa-aes
```

## Usage

Here's a complete example showing how to encrypt and decrypt messages between two parties:

```typescript
import { ECDSAAES } from '@eliza-dot-aes/ecdsa-aes';

async function main() {
    // Initialize Alice and Bob with their private keys
    // Note: These can be Ethereum private keys
    const alice = await ECDSAAES.build(
        "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5e"
    );
    const bob = await ECDSAAES.build(
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

### ECDSAAES

Main class for handling encrypted message operations.

#### Constructor

```typescript
constructor(seedOrprivateKey: string)
```

- `seedOrprivateKey`: Hexadecimal string of private key (can be an Ethereum private key)

#### Methods

```typescript
// Encrypt a message
async encryptMessage(message: string, toPublicKey: Uint8Array): Promise<string>

// Decrypt a message
async decryptMessage(message: string): Promise<string>
```

## Technical Details

1. Key Generation:
   - Uses secp256k1 curve (same as Ethereum)
   - Compatible with existing Ethereum private keys
   - Generates uncompressed public keys (65 bytes)

2. Key Exchange:
   - ECDH (Elliptic Curve Diffie-Hellman) on secp256k1
   - Uses the noble/curves implementation for secure key operations
   - Shared secret generation through ECDH

## Security Features

- Uses secp256k1 ECDH for secure key exchange
- AES-256-CBC for symmetric encryption
- HMAC-SHA512 for message authentication
- Random padding for message length obfuscation
- Secure key derivation from shared secrets
- Compatible with Ethereum's cryptographic standards

## Ethereum Compatibility

This package uses the same elliptic curve (secp256k1) as Ethereum, which means:
- You can use your Ethereum private keys
- Compatible with Ethereum key generation tools
- Follows the same security standards as Ethereum

## License

Apache License 2.0
