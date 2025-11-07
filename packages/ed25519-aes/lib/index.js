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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ED25519AES = void 0;
const common_1 = require("@eliza-dot-aes/common");
const ed25519_js_1 = require("@noble/curves/ed25519.js");
const ed25519_js_2 = require("@noble/curves/ed25519.js");
const getSharedSecretCallBack = (privateKey, toPublicKey) => {
    return Promise.resolve(ed25519_js_2.x25519.getSharedSecret(privateKey, toPublicKey));
};
const getPublicKeyAndPrivateKeyCallBack = (seedOrprivateKey) => {
    const kp = ed25519_js_1.ed25519.keygen(seedOrprivateKey);
    const privateKey = ed25519_js_1.ed25519.utils.toMontgomerySecret(kp.secretKey);
    const publicKey = ed25519_js_1.ed25519.utils.toMontgomery(kp.publicKey);
    return Promise.resolve([publicKey, privateKey]);
};
class ED25519AES extends common_1.CryptMessage {
    static async build(seedOrprivateKey) {
        return await super.build(seedOrprivateKey, 'ed25519', getSharedSecretCallBack, getPublicKeyAndPrivateKeyCallBack);
    }
}
exports.ED25519AES = ED25519AES;
//# sourceMappingURL=index.js.map