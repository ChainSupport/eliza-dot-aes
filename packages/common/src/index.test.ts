
import { describe, it, expect } from 'vitest';
import * as sr25519 from '@scure/sr25519';
import { CryptMessage} from './index';
import { hexToBytes, utf8ToBytes } from "ethereum-cryptography/utils.js";
import { convertJsonToEncryptedMemo } from './utils';

describe('CryptMessage with sr25519', () => {
    const getPublicKeyAndPrivateKey = async (seedOrPrivateKey: Uint8Array): Promise<[Uint8Array, Uint8Array]> => {
        const privateKey = sr25519.secretFromSeed(seedOrPrivateKey);
        const publicKey = sr25519.getPublicKey(privateKey);
        return [publicKey, privateKey];
    };

    const getSharedSecret = async (privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> => {
        return sr25519.getSharedSecret(privateKey, publicKey);
    };
    const aliceSeed = "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5e";
    const bobSeed = "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c50";


    // fixme 
    it('should throw error when seed is invalid', () => {
        // const invalidSeed = "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5g";
        // expect(() => CryptMessage.build(invalidSeed, "sr25519", getSharedSecret, getPublicKeyAndPrivateKey))
        //     .toThrow();
        // const invalidSeed1 = "hahaha";
        // expect(() => CryptMessage.build(invalidSeed1, "sr25519", getSharedSecret, getPublicKeyAndPrivateKey))
        //     .toThrow();
    });

    it('should encrypt and decrypt message successfully', async () => {

        const alice = await CryptMessage.build(
            aliceSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        const bob = await CryptMessage.build(
            bobSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        const originalMessage = "Hello, Bob! This is a secret message.";

        const encryptedMessage = await alice.encryptMessage(originalMessage, bob.publicKey);
        expect(encryptedMessage).toBeDefined();
        expect(typeof encryptedMessage).toBe('string');

        const decryptedMessage = await bob.decryptMessage(encryptedMessage);
        expect(decryptedMessage).toBe(originalMessage);
    });

    it('should throw error when message is empty', async () => {
        const alice = await CryptMessage.build(
            aliceSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        const bob = await CryptMessage.build(
            bobSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        await expect(alice.encryptMessage("", bob.publicKey))
            .rejects
            .toThrow("encryptMessage error: Error: message is empty");
    });

    it('should throw error when public key length not match', async () => {
        const alice = await CryptMessage.build(
            aliceSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        const wrongPublicKey = new Uint8Array(10); 
        await expect(alice.encryptMessage("test message", wrongPublicKey))
            .rejects
            .toThrow("toPublicKey length not match");
    });

    it('should support bidirectional encryption and decryption', async () => {
        const alice = await CryptMessage.build(
            aliceSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        const bob = await CryptMessage.build(
            bobSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        const aliceMessage = "Hello Bob, this is Alice!";
        const encryptedAliceMessage = await alice.encryptMessage(aliceMessage, bob.publicKey);
        const bobReceivedMessage = await bob.decryptMessage(encryptedAliceMessage);
        expect(bobReceivedMessage).toBe(aliceMessage);

        const bobMessage = "Hi Alice, I got your message!";
        const encryptedBobMessage = await bob.encryptMessage(bobMessage, alice.publicKey);
        const aliceReceivedMessage = await alice.decryptMessage(encryptedBobMessage);
        expect(aliceReceivedMessage).toBe(bobMessage);
    });

    it('should handle long messages correctly', async () => {
        const alice = await CryptMessage.build(
            aliceSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        const bob = await CryptMessage.build(
            bobSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        const longMessage = 'A'.repeat(1000) + 'B'.repeat(1000) + 'C'.repeat(1000);
  
        const encryptedMessage = await alice.encryptMessage(longMessage, bob.publicKey);
        expect(encryptedMessage).toBeDefined();
        expect(typeof encryptedMessage).toBe('string');

        const decryptedMessage = await bob.decryptMessage(encryptedMessage);
        expect(decryptedMessage).toBe(longMessage);
        expect(decryptedMessage.length).toBe(3000);
    });

    it('should throw error when salt is empty in hmacSha512', async () => {
        const alice = await CryptMessage.build(
            aliceSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        // Mock publicKey to be empty
        alice.publicKey = new Uint8Array(0);

        await expect(alice.encryptMessage("test", new Uint8Array(32)))
            .rejects
            .toThrow();
    });

    it('should throw error when data is empty in aesDecryptData', async () => {
        const bob = await CryptMessage.build(
            bobSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        // Mock an empty encrypted message
        const emptyMessage = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(48))));
        await expect(bob.decryptMessage(emptyMessage))
            .rejects
            .toThrow("data is empty");
    });

    it('should throw error for invalid base64 in decryptMessage', async () => {
        const bob = await CryptMessage.build(
            bobSeed,
            "sr25519",
            getSharedSecret,
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        // Invalid base64 string
        const invalidBase64 = "!@#$%^&*()";
        await expect(bob.decryptMessage(invalidBase64))
            .rejects
            .toThrow();
    });

    it('should throw error when getSharedSecret fails', async () => {
        const alice = await CryptMessage.build(
            aliceSeed,
            "sr25519",
            async () => { throw new Error("Failed to get shared secret"); },
            getPublicKeyAndPrivateKey
        );

        // await new Promise(resolve => setTimeout(resolve, 100));

        await expect(alice.encryptMessage("test", new Uint8Array(32)))
            .rejects
            .toThrow("Failed to get shared secret");
    });

});

describe('convertJsonToEncryptedMemo', () => {
    it('should convert valid JSON to EncryptedMemo', () => {
        const validJson = JSON.stringify({
            e: "encrypted_data",
            t: "sr25519",
            to: "recipient_address"
        });

        const result = convertJsonToEncryptedMemo(validJson);
        expect(result).toEqual({
            e: "encrypted_data",
            t: "sr25519",
            to: "recipient_address"
        });
    });

    it('should throw error for invalid JSON format', () => {
        const invalidJson = "not a json string";
        
        expect(() => convertJsonToEncryptedMemo(invalidJson))
            .toThrow('convertJsonToEncryptedMemo error: SyntaxError: Unexpected token \'o\', "not a json string" is not valid JSON');
    });

    it('should throw error for missing required fields', () => {
        const invalidJson = JSON.stringify({
            e: "encrypted_data",
            // missing 't' field
            to: "recipient_address"
        });

        expect(() => convertJsonToEncryptedMemo(invalidJson))
            .toThrow();
    });

    it('should throw error for extra fields', () => {
        const invalidJson = JSON.stringify({
            e: "encrypted_data",
            t: "sr25519",
            to: "recipient_address",
            extra: "unexpected_field"  // extra field
        });

        expect(() => convertJsonToEncryptedMemo(invalidJson))
            .toThrow();
    });

    it('should throw error for invalid field types', () => {
        const invalidJson = JSON.stringify({
            e: 123,  // should be string
            t: "sr25519",
            to: "recipient_address"
        });

        expect(() => convertJsonToEncryptedMemo(invalidJson))
            .toThrow();
    });
});