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
import { KeypairType } from "./interfaces";
import { ICryptMessage } from "./interfaces";
/**
 * A class for handling encrypted message operations
 * Provides message encryption and decryption functionality based on different key types (sr25519, ed25519, ethereum)
 */
export declare class CryptMessage implements ICryptMessage {
    publicKey: Uint8Array;
    publicKeyLength: number;
    keyPairType: KeypairType;
    protected privateKey: Uint8Array;
    protected getSharedSecretCallBack: (privateKey: Uint8Array, publicKey: Uint8Array) => Promise<Uint8Array>;
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
    static build(seedOrprivateKey: string, keyPairType: KeypairType, getSharedSecretCallBack: (privateKey: Uint8Array, publicKey: Uint8Array) => Promise<Uint8Array>, getPublicKeyAndPrivateKeyCallBack: (seedOrprivateKey: Uint8Array) => Promise<[Uint8Array, Uint8Array]>): Promise<CryptMessage>;
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
    private init;
    /**
     * Gets the key pair type
     * @returns Key pair type
     */
    getKeyPairType(): KeypairType;
    /**
     * Encrypts a message
     * @param message Plaintext message to encrypt
     * @param toPublicKey Recipient's public key
     * @returns Base64 encoded encrypted message
     * @throws When message is empty or public key length doesn't match
     */
    encryptMessage(message: string, toPublicKey: Uint8Array): Promise<string>;
    /**
     * Decrypts a message
     * @param message Base64 encoded encrypted message
     * @returns Decrypted plaintext message
     * @throws When message is empty or format is invalid
     */
    decryptMessage(message: string): Promise<string>;
    /**
     * Gets the shared secret
     * @param toPublicKey Recipient's public key
     * @returns Shared secret key
     * @throws When shared secret generation fails
     */
    getSharedSecret(toPublicKey: Uint8Array): Promise<Uint8Array>;
}
export * from './interfaces';
export * from './utils';
//# sourceMappingURL=index.d.ts.map