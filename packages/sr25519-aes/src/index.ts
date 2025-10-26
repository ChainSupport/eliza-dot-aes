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

import { CryptMessage } from "@eliza-dot-aes/common";
import * as sr25519 from '@scure/sr25519';


const getSharedSecretCallBack = (privateKey: Uint8Array, toPublicKey: Uint8Array) => {
  return Promise.resolve(sr25519.getSharedSecret(privateKey, toPublicKey));
};

const getPublicKeyAndPrivateKeyCallBack = async (seedOrprivateKey: Uint8Array): Promise<[Uint8Array, Uint8Array]> => {
  const privateKey = sr25519.secretFromSeed(seedOrprivateKey);
  const publicKey = sr25519.getPublicKey(privateKey);
  return [publicKey, privateKey];
};

export class SR25519AES extends CryptMessage {
  static async build(seedOrprivateKey: string): Promise<SR25519AES> {
    return await super.build(seedOrprivateKey, 'sr25519', getSharedSecretCallBack, getPublicKeyAndPrivateKeyCallBack);
  }
}
