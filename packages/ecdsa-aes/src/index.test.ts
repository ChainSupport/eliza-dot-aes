
import { describe, it, expect } from 'vitest';
import { ECDSAAES } from './index';

describe('ECDSAAES', () => {
  const alicePrivateKey = "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5e";
  const bobPrivateKey = "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5d";

  it('should encrypt message from Alice to Bob and Bob can decrypt it', async () => {
      // Initialize Alice and Bob's instances
      const alice = await ECDSAAES.build(alicePrivateKey);
    const bob = await ECDSAAES.build(bobPrivateKey);

    // Wait for initialization
    // await new Promise(resolve => setTimeout(resolve, 100));

    // Alice encrypts message for Bob
    const originalMessage = "Hello Bob! This is a secret message from Alice.";
    const encryptedMessage = await alice.encryptMessage(originalMessage, bob.publicKey);

    // Bob decrypts Alice's message
    const decryptedMessage = await bob.decryptMessage(encryptedMessage);
    
    expect(decryptedMessage).toBe(originalMessage);
  });

  it('should encrypt message from Bob to Alice and Alice can decrypt it', async () => {
    // Initialize Alice and Bob's instances
    const alice = await ECDSAAES.build(alicePrivateKey);
    const bob = await ECDSAAES.build(bobPrivateKey);

    // Wait for initialization
    // await new Promise(resolve => setTimeout(resolve, 100));

    // Bob encrypts message for Alice
    const originalMessage = "Hi Alice! Got your message, here's my secret reply.";
    const encryptedMessage = await bob.encryptMessage(originalMessage, alice.publicKey);

    // Alice decrypts Bob's message
    const decryptedMessage = await alice.decryptMessage(encryptedMessage);
    
    expect(decryptedMessage).toBe(originalMessage);
  });

  it('For the same message and the same private key, Alice\'s encryption results are different each time (no decryption is required).', async () => {
    const alice = await ECDSAAES.build(alicePrivateKey);
    const bob = await ECDSAAES.build(bobPrivateKey);
    const originalMessage = "Hello Bob! This is a secret message from Alice.";
    const encryptedMessage1 = await alice.encryptMessage(originalMessage, bob.publicKey);
    const encryptedMessage2 = await alice.encryptMessage(originalMessage, bob.publicKey);
    expect(encryptedMessage1).not.toBe(encryptedMessage2);
  });


  it('should handle long messages in both directions', async () => {
    const alice = await ECDSAAES.build(alicePrivateKey);
    const bob = await ECDSAAES.build(bobPrivateKey);

    // Wait for initialization
    // await new Promise(resolve => setTimeout(resolve, 100));

    // Long message test from Alice to Bob
    const longMessage = "A".repeat(1000) + "中文测试" + "B".repeat(1000);
    const encryptedLongMessage = await alice.encryptMessage(longMessage, bob.publicKey);
    const decryptedLongMessage = await bob.decryptMessage(encryptedLongMessage);
    expect(decryptedLongMessage).toBe(longMessage);

    // Long message test from Bob to Alice
    const bobLongMessage = "X".repeat(1000) + "测试中文" + "Y".repeat(1000);
    const bobEncryptedMessage = await bob.encryptMessage(bobLongMessage, alice.publicKey);
    const bobDecryptedMessage = await alice.decryptMessage(bobEncryptedMessage);
    expect(bobDecryptedMessage).toBe(bobLongMessage);
  });
});