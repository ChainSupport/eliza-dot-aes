/**
 * Copyright 2025 weimeme
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as aes from "ethereum-cryptography/aes.js";
import jsSHA from "jssha";
import {z} from "zod";
import { KeypairType } from "./interfaces";
import { hexToBytes, utf8ToBytes } from "ethereum-cryptography/utils.js";
import { ICryptMessage } from "./interfaces";

/**
 * A class for handling encrypted message operations
 * Provides message encryption and decryption functionality based on different key types (sr25519, ed25519, ethereum)
 */
export class CryptMessage implements ICryptMessage{
    public publicKey!: Uint8Array;
    public publicKeyLength!: number;
    public keyPairType!: KeypairType;
    protected privateKey!: Uint8Array;
    protected getSharedSecretCallBack!: (privateKey: Uint8Array, publicKey: Uint8Array) => Promise<Uint8Array>;

    /**
     * Creates a new instance of CryptMessage asynchronously
     * @param seedOrprivateKey Hexadecimal string of seed(polkadot) or private(ethereum) key
     * @param keyPairType Type of key pair (sr25519, ed25519, ethereum)
     * @param getSharedSecretCallBack Callback function to generate shared secret from private and public keys
     * @param getPublicKeyAndPrivateKeyCallBack Callback function to generate key pair from seed
     * @returns Promise resolving to a new CryptMessage instance
     * @throws When seed format is invalid or key generation fails
     * @example
     * const cryptMessage = await CryptMessage.build(
     *   "0x9d61b19deffd5020afb5b1a7877f2e1e0a4f5c5e0a4f5c5e0a4f5c5e0a4f5c5e",
     *   "sr25519",
     *   getSharedSecretCallBack,
     *   getPublicKeyAndPrivateKeyCallBack
     * );
     */
    static async build(seedOrprivateKey: string, keyPairType: KeypairType, getSharedSecretCallBack: (privateKey: Uint8Array, publicKey: Uint8Array) => Promise<Uint8Array>, getPublicKeyAndPrivateKeyCallBack: (seedOrprivateKey: Uint8Array) => Promise<[Uint8Array, Uint8Array]>): Promise<CryptMessage> {
        const cryptMessage = new CryptMessage();
        await cryptMessage.init(seedOrprivateKey, keyPairType, getSharedSecretCallBack, getPublicKeyAndPrivateKeyCallBack);
        return cryptMessage;
    }

    /**
     * Initializes a CryptMessage instance with the provided parameters
     * @param seedOrprivateKey Hexadecimal string of seed(polkadot) or private(ethereum) key
     * @param keyPairType Type of key pair (sr25519, ed25519, ethereum)
     * @param getSharedSecretCallBack Callback function to generate shared secret from private and public keys
     * @param getPublicKeyAndPrivateKeyCallBack Callback function to generate key pair from seed
     * @returns Promise resolving to the initialized CryptMessage instance
     * @throws When seed format is invalid or key generation fails
     * @private Internal method used by build()
     */
    private async init(seedOrprivateKey: string, keyPairType: KeypairType, getSharedSecretCallBack: (privateKey: Uint8Array, publicKey: Uint8Array) => Promise<Uint8Array>, getPublicKeyAndPrivateKeyCallBack: (seedOrprivateKey: Uint8Array) => Promise<[Uint8Array, Uint8Array]>): Promise<CryptMessage> {
        const seedOrprivateKeyBytes: Uint8Array = hexToBytes(seedOrprivateKey);
        getPublicKeyAndPrivateKeyCallBack(seedOrprivateKeyBytes).then(([publicKey, privateKey]) => {
            this.publicKey = publicKey;
            this.publicKeyLength = publicKey.length;
            this.privateKey = privateKey;
            this.keyPairType = keyPairType;
            this.getSharedSecretCallBack = getSharedSecretCallBack;
        }).catch((error) => {
            throw new Error(`CryptMessage constructor error:${error}`);
        });
        return this;
    }

    /**
     * Gets the key pair type
     * @returns Key pair type
     */
    public getKeyPairType(): KeypairType {
        return this.keyPairType;
    }

    /**
     * Encrypts a message
     * @param message Plaintext message to encrypt
     * @param toPublicKey Recipient's public key
     * @returns Base64 encoded encrypted message
     * @throws When message is empty or public key length doesn't match
     */
    public async encryptMessage(message: string, toPublicKey: Uint8Array): Promise<string> {
        try {
            if (toPublicKey.length !== this.publicKeyLength) {
                throw new Error("toPublicKey length not match");
            }
            if (!message) throw new Error("message is empty");
            const messageBytes = new TextEncoder().encode(message);
            const myPublicKeyBytes: Uint8Array = this.publicKey;
            const salt: Uint8Array = this.publicKey;
            const sharedSecret: Uint8Array = await this.getSharedSecret(toPublicKey);
            const randomPrefix: Uint8Array = getRandomPrefix(messageBytes.length, 16);
            const messageBytesWithPrefix: Uint8Array = new Uint8Array([...randomPrefix, ...messageBytes]);
            const dataHash: Uint8Array = hmacSha512(salt, messageBytesWithPrefix);
            const msgKey: Uint8Array = dataHash.slice(0, 16);
            const cbcStateSecret: Uint8Array = getCbcStateSecret(sharedSecret, msgKey);
            const encryptedData: Uint8Array = await aesEncryptData(cbcStateSecret, messageBytesWithPrefix);
            const theirPublicKey: Uint8Array = getTheirPublicKey(myPublicKeyBytes, toPublicKey, this.publicKeyLength);
            const res = new Uint8Array([...theirPublicKey, ...msgKey, ...encryptedData]);
            return btoa(String.fromCharCode.apply(null, Array.from(res)));
        } catch (error) {
            throw new Error(`encryptMessage error: ${error}`);
        }
    }

    /**
     * Decrypts a message
     * @param message Base64 encoded encrypted message
     * @returns Decrypted plaintext message
     * @throws When message is empty or format is invalid
     */
    public async decryptMessage(message: string): Promise<string> {
        try {
            if (!message) throw new Error("message is empty");
            const messageBytes = new Uint8Array(atob(message).split("").map((c) => c.charCodeAt(0)));
            const p: Uint8Array = messageBytes.slice(0, this.publicKeyLength);
            const theirPublicKey: Uint8Array = getTheirPublicKey(this.publicKey, p, this.publicKeyLength);
            const sharedSecret: Uint8Array = await this.getSharedSecret(theirPublicKey);
            const msgKey: Uint8Array = messageBytes.slice(this.publicKeyLength, this.publicKeyLength + 16);
            const cbcStateSecret: Uint8Array = getCbcStateSecret(sharedSecret, msgKey);
            const encryptedData: Uint8Array = messageBytes.slice(this.publicKeyLength + 16);
            const decryptedData: Uint8Array = await aesDecryptData(cbcStateSecret, encryptedData);
            const data: Uint8Array = decryptedData.slice(decryptedData[0]);
            return new TextDecoder().decode(data);
        } catch (error) {
            throw new Error(`decryptMessage error: ${error}`);
        }
    }

    /**
     * Gets the shared secret
     * @param toPublicKey Recipient's public key
     * @returns Shared secret key
     * @throws When shared secret generation fails
     */
    public async getSharedSecret(toPublicKey: Uint8Array): Promise<Uint8Array> {
        return this.getSharedSecretCallBack(this.privateKey, toPublicKey);
    }
}

/**
 * Calculates HMAC-SHA512 hash
 * @param salt Salt value for HMAC
 * @param data Data to hash
 * @returns 64-byte hash value
 * @throws When data is empty
 */
function hmacSha512(salt: Uint8Array, data: Uint8Array): Uint8Array {
    if (!data) throw new Error("data is empty");
    const shaObj = new jsSHA("SHA-512", "UINT8ARRAY", {
    hmacKey: { value: salt, format: "UINT8ARRAY" },
    });
    shaObj.update(data);
    const hash = shaObj.getHash("UINT8ARRAY");
    return hash;
}

/**
 * Encrypts data using AES-CBC
 * @param secret 48-byte secret (32 bytes for AES key, 16 bytes for IV)
 * @param data Data to encrypt
 * @returns Encrypted data
 * @throws When data is empty or secret length is insufficient
 */
async function aesEncryptData(secret: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    if (!data) throw new Error("data is empty");
    if (data.length === 0) throw new Error("data is empty");
    const key = secret.slice(0, 32);
    const iv = secret.slice(32, 32 + 16);
    return aes.encrypt(data, key, iv, "aes-256-cbc");
}

/**
 * Decrypts data using AES-CBC
 * @param secret 48-byte secret (32 bytes for AES key, 16 bytes for IV)
 * @param data Data to decrypt
 * @returns Decrypted data
 * @throws When data is empty or secret length is insufficient
 */
async function aesDecryptData(secret: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    if (!data) throw new Error("data is empty");
    if (data.length === 0) throw new Error("data is empty");
    const key = secret.slice(0, 32);
    const iv = secret.slice(32, 32 + 16);
    return aes.decrypt(data, key, iv, "aes-256-cbc");
}

/**
 * Generates CBC state secret
 * @param sharedSecret Shared secret key
 * @param msgKey Message key
 * @returns CBC state secret
 */
function getCbcStateSecret(sharedSecret: Uint8Array, msgKey: Uint8Array) {
    return hmacSha512(sharedSecret, msgKey);
}

/**
 * Computes XOR of two public keys
 * @param p1 First public key
 * @param p2 Second public key
 * @param publicKeyLen Length of public keys
 * @returns XORed public key
 */
function getTheirPublicKey(p1: Uint8Array, p2: Uint8Array, publicKeyLen: number): Uint8Array {
    let theirPublicKey = new Uint8Array(publicKeyLen);
    for (let i = 0; i < publicKeyLen; i++) {
        theirPublicKey[i] = p1[i] ^ p2[i];
    }
    return theirPublicKey;
}

/**
 * Generates random prefix for message padding
 * @param dataLength Length of data to pad
 * @param minPadding Minimum padding length
 * @returns Random prefix array
 */
function getRandomPrefix(dataLength: number, minPadding: number): Uint8Array {
    const prefixLength: number = ((minPadding + 15 + dataLength) & -16) - dataLength;
    const prefix: Uint8Array = crypto.getRandomValues(new Uint8Array(prefixLength));
    prefix[0] = prefixLength;
    return prefix;
}

export * from './interfaces';
export * from './utils';