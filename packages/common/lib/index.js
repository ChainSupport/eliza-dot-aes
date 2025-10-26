"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptMessage = void 0;
const aes = __importStar(require("ethereum-cryptography/aes.js"));
const jssha_1 = __importDefault(require("jssha"));
const utils_js_1 = require("ethereum-cryptography/utils.js");
/**
 * A class for handling encrypted message operations
 * Provides message encryption and decryption functionality based on different key types (sr25519, ed25519, ethereum)
 */
class CryptMessage {
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
    static async build(seedOrprivateKey, keyPairType, getSharedSecretCallBack, getPublicKeyAndPrivateKeyCallBack) {
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
    async init(seedOrprivateKey, keyPairType, getSharedSecretCallBack, getPublicKeyAndPrivateKeyCallBack) {
        const seedOrprivateKeyBytes = (0, utils_js_1.hexToBytes)(seedOrprivateKey);
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
    getKeyPairType() {
        return this.keyPairType;
    }
    /**
     * Encrypts a message
     * @param message Plaintext message to encrypt
     * @param toPublicKey Recipient's public key
     * @returns Base64 encoded encrypted message
     * @throws When message is empty or public key length doesn't match
     */
    async encryptMessage(message, toPublicKey) {
        try {
            if (toPublicKey.length !== this.publicKeyLength) {
                throw new Error("toPublicKey length not match");
            }
            if (!message)
                throw new Error("message is empty");
            const messageBytes = new TextEncoder().encode(message);
            const myPublicKeyBytes = this.publicKey;
            const salt = this.publicKey;
            const sharedSecret = await this.getSharedSecret(toPublicKey);
            const randomPrefix = getRandomPrefix(messageBytes.length, 16);
            const messageBytesWithPrefix = new Uint8Array([...randomPrefix, ...messageBytes]);
            const dataHash = hmacSha512(salt, messageBytesWithPrefix);
            const msgKey = dataHash.slice(0, 16);
            const cbcStateSecret = getCbcStateSecret(sharedSecret, msgKey);
            const encryptedData = await aesEncryptData(cbcStateSecret, messageBytesWithPrefix);
            const theirPublicKey = getTheirPublicKey(myPublicKeyBytes, toPublicKey, this.publicKeyLength);
            const res = new Uint8Array([...theirPublicKey, ...msgKey, ...encryptedData]);
            return btoa(String.fromCharCode.apply(null, Array.from(res)));
        }
        catch (error) {
            throw new Error(`encryptMessage error: ${error}`);
        }
    }
    /**
     * Decrypts a message
     * @param message Base64 encoded encrypted message
     * @returns Decrypted plaintext message
     * @throws When message is empty or format is invalid
     */
    async decryptMessage(message) {
        try {
            if (!message)
                throw new Error("message is empty");
            const messageBytes = new Uint8Array(atob(message).split("").map((c) => c.charCodeAt(0)));
            const p = messageBytes.slice(0, this.publicKeyLength);
            const theirPublicKey = getTheirPublicKey(this.publicKey, p, this.publicKeyLength);
            const sharedSecret = await this.getSharedSecret(theirPublicKey);
            const msgKey = messageBytes.slice(this.publicKeyLength, this.publicKeyLength + 16);
            const cbcStateSecret = getCbcStateSecret(sharedSecret, msgKey);
            const encryptedData = messageBytes.slice(this.publicKeyLength + 16);
            const decryptedData = await aesDecryptData(cbcStateSecret, encryptedData);
            const data = decryptedData.slice(decryptedData[0]);
            return new TextDecoder().decode(data);
        }
        catch (error) {
            throw new Error(`decryptMessage error: ${error}`);
        }
    }
    /**
     * Gets the shared secret
     * @param toPublicKey Recipient's public key
     * @returns Shared secret key
     * @throws When shared secret generation fails
     */
    async getSharedSecret(toPublicKey) {
        return this.getSharedSecretCallBack(this.privateKey, toPublicKey);
    }
}
exports.CryptMessage = CryptMessage;
/**
 * Calculates HMAC-SHA512 hash
 * @param salt Salt value for HMAC
 * @param data Data to hash
 * @returns 64-byte hash value
 * @throws When data is empty
 */
function hmacSha512(salt, data) {
    if (!data)
        throw new Error("data is empty");
    const shaObj = new jssha_1.default("SHA-512", "UINT8ARRAY", {
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
async function aesEncryptData(secret, data) {
    if (!data)
        throw new Error("data is empty");
    if (data.length === 0)
        throw new Error("data is empty");
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
async function aesDecryptData(secret, data) {
    if (!data)
        throw new Error("data is empty");
    if (data.length === 0)
        throw new Error("data is empty");
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
function getCbcStateSecret(sharedSecret, msgKey) {
    return hmacSha512(sharedSecret, msgKey);
}
/**
 * Computes XOR of two public keys
 * @param p1 First public key
 * @param p2 Second public key
 * @param publicKeyLen Length of public keys
 * @returns XORed public key
 */
function getTheirPublicKey(p1, p2, publicKeyLen) {
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
function getRandomPrefix(dataLength, minPadding) {
    const prefixLength = ((minPadding + 15 + dataLength) & -16) - dataLength;
    const prefix = crypto.getRandomValues(new Uint8Array(prefixLength));
    prefix[0] = prefixLength;
    return prefix;
}
__exportStar(require("./interfaces"), exports);
__exportStar(require("./utils"), exports);
//# sourceMappingURL=index.js.map