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
exports.ECDSAAES = void 0;
const common_1 = require("@eliza-dot-aes/common");
const secp256k1_js_1 = require("@noble/curves/secp256k1.js");
const getSharedSecretCallBack = (privateKey, toPublicKey) => {
    return Promise.resolve(secp256k1_js_1.secp256k1.getSharedSecret(privateKey, toPublicKey));
};
const getPublicKeyAndPrivateKeyCallBack = (seedOrprivateKey) => {
    const privateKey = seedOrprivateKey;
    const publicKey = secp256k1_js_1.secp256k1.getPublicKey(privateKey);
    return Promise.resolve([publicKey, privateKey]);
};
class ECDSAAES extends common_1.CryptMessage {
    static async build(seedOrprivateKey) {
        return await super.build(seedOrprivateKey, 'ethereum', getSharedSecretCallBack, getPublicKeyAndPrivateKeyCallBack);
    }
}
exports.ECDSAAES = ECDSAAES;
//# sourceMappingURL=index.js.map