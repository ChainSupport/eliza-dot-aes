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
exports.convertJsonToEncryptedMemo = convertJsonToEncryptedMemo;
const zod_1 = require("zod");
const encryptedMemoSchema = zod_1.z.object({
    e: zod_1.z.string(),
    t: zod_1.z.string(),
    to: zod_1.z.string(),
}).strict();
function convertJsonToEncryptedMemo(message) {
    try {
        const r = JSON.parse(message);
        const res = encryptedMemoSchema.parse(r);
        return {
            e: res.e,
            t: res.t,
            to: res.to
        };
    }
    catch (error) {
        throw new Error(`convertJsonToEncryptedMemo error: ${error}`);
    }
}
//# sourceMappingURL=utils.js.map