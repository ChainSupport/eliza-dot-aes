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


import {z} from "zod";
import { EncryptedMemo } from "./interfaces";

const encryptedMemoSchema = z.object({
  e: z.string(),
  t: z.string(),
  to: z.string(),
}).strict();

type EncryptedMemoType = z.infer<typeof encryptedMemoSchema>;

export function convertJsonToEncryptedMemo(message: string): EncryptedMemo {
  try {
      const r: EncryptedMemoType = JSON.parse(message);
      const res = encryptedMemoSchema.parse(r);
      return {
          e: res.e,
          t: res.t, 
          to: res.to
      } as EncryptedMemo;
  } catch (error) {
      throw new Error(`convertJsonToEncryptedMemo error: ${error}`);
  }
}
