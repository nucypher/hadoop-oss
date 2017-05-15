/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.crypto.key.pre;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EncryptedKeyVersion;

import java.io.IOException;
import java.security.GeneralSecurityException;

@InterfaceAudience.Private
@InterfaceStability.Unstable
public interface ReEncryptionKeyProviderInterface {
    final class ReEncryptionKeyInstance
    {
        private final String name;
        private final byte[] material;

        public String getName() {
            return name;
        }

        public byte[] getMaterial() {
            return material;
        }

      public ReEncryptionKeyInstance(String srcEncryptionKeyName, String dstEncryptionKeyName, byte[] material) {
        this.name = getReEncryptionKeyName(srcEncryptionKeyName, dstEncryptionKeyName);
        this.material = material;
      }

      public ReEncryptionKeyInstance(String name, byte[] material) {
          this.name = name;
          this.material = material;
      }

      public ReEncryptionKeyInstance(String name) {
        this.name = name;
        this.material = null;
      }
      @Override
      public int hashCode() {
        return name.hashCode();
      }

      public static String getReEncryptionKeyName(String srcEncryptionKeyName, String dstEncryptionKeyName)
      {
        return srcEncryptionKeyName + "->" + dstEncryptionKeyName;
      }

      public String getSrcNameVersion()
          throws IOException
      {
        int div = name.lastIndexOf("->");
        if (div == -1) {
          throw new IOException("Incorrect re-encryption key" + name);
        }
        return name.substring(0, div);
      }

      public String getDstNameVersion()
          throws IOException
      {
        int div = name.lastIndexOf("->");
        if (div == -1) {
          throw new IOException("Incorrect re-encryption key" + name);
        }
        return name.substring(div + 2);
      }
    }

  /**
   * Transform encrypted key <code>encryptedKeyVersion</code> with re-encryption key to <code>destinationEncryptionKey</code>, stored inside node
   * @param encryptedKeyVersion
   * @param destinationEncryptionKey
   * @return
   */
    EncryptedKeyVersion transformEncryptedKey(EncryptedKeyVersion encryptedKeyVersion, String destinationEncryptionKey)
        throws IOException, GeneralSecurityException;


  /**
   * Delete re-encryption key <code>name</code>
   * @param srcName
   * @param dstName
   */
  void deleteReEncryptionKey(String srcName, String dstName);
}
