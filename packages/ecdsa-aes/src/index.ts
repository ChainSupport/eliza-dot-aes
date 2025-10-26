
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


import {CryptMessage} from "@eliza-dot-aes/common";
import { hexToBytes, utf8ToBytes } from "ethereum-cryptography/utils.js";
import { secp256k1 } from '@noble/curves/secp256k1.js';

const getSharedSecretCallBack = (privateKey: Uint8Array, toPublicKey: Uint8Array) => {
  return Promise.resolve(secp256k1.getSharedSecret(privateKey, toPublicKey));
};

const getPublicKeyAndPrivateKeyCallBack = (seedOrprivateKey: Uint8Array): Promise<[Uint8Array, Uint8Array]> => {
  const privateKey = seedOrprivateKey;
  const publicKey = secp256k1.getPublicKey(privateKey);
  return Promise.resolve([publicKey, privateKey]);
};

export class ECDSAAES extends CryptMessage {

  static async build(seedOrprivateKey: string): Promise<ECDSAAES> {
    return await super.build(seedOrprivateKey, 'ethereum', getSharedSecretCallBack, getPublicKeyAndPrivateKeyCallBack);
  }
}