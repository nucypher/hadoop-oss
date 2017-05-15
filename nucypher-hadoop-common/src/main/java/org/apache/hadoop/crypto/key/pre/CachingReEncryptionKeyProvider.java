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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EncryptedKeyVersion;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class CachingReEncryptionKeyProvider extends
    AbstractReEncryptionKeyProvider {

    private final AbstractReEncryptionKeyProvider provider;
    private LoadingCache<ReEncryptionKeyCacheKey, ReEncryptionKeyInstance> reEncryptionKeyCache;
    private Cache<EncryptedKeyCacheKey, EncryptedKeyVersion> transformedEEKCache;

  private class ReEncryptionKeyCacheKey
  {
    private String srcKeyName;
    private String dstKeyName;

    public ReEncryptionKeyCacheKey(String srcKeyName, String dstKeyName) {
      this.srcKeyName = srcKeyName;
      this.dstKeyName = dstKeyName;
    }

    public String getSrcKeyName() {
      return srcKeyName;
    }

    public String getDstKeyName() {
      return dstKeyName;
    }
    public String toString()
    {
        return srcKeyName + "->" + dstKeyName;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      ReEncryptionKeyCacheKey that = (ReEncryptionKeyCacheKey) o;

      if (srcKeyName != null ? !srcKeyName.equals(that.srcKeyName) : that.srcKeyName != null) return false;
      return dstKeyName != null ? dstKeyName.equals(that.dstKeyName) : that.dstKeyName == null;

    }

    @Override
    public int hashCode() {
      int result = srcKeyName != null ? srcKeyName.hashCode() : 0;
      result = 31 * result + (dstKeyName != null ? dstKeyName.hashCode() : 0);
      return result;
    }
  }

  private class EncryptedKeyCacheKey
  {
    private ReEncryptionKeyCacheKey reEncryptionKey;
    private String encryptedKeyVersion;

    public EncryptedKeyCacheKey(ReEncryptionKeyCacheKey reEncryptionKey, String encryptedKeyVersion) {
      this.reEncryptionKey = reEncryptionKey;
      this.encryptedKeyVersion = encryptedKeyVersion;
    }

    public ReEncryptionKeyCacheKey getReEncryptionKey() {
      return reEncryptionKey;
    }

    public String getEncryptedKeyVersion() {
      return encryptedKeyVersion;
    }
  }

  public CachingReEncryptionKeyProvider(AbstractReEncryptionKeyProvider prov, long keyTimeoutMillis,
        long eekTimeoutMillis) {
      super(prov.getConf());
      this.provider = prov;
      reEncryptionKeyCache =
          CacheBuilder.newBuilder().expireAfterAccess(keyTimeoutMillis,
              TimeUnit.MILLISECONDS)
              .build(new CacheLoader<ReEncryptionKeyCacheKey, ReEncryptionKeyInstance>() {
                @Override
                public ReEncryptionKeyInstance load(ReEncryptionKeyCacheKey key) throws Exception {
                  ReEncryptionKeyInstance kv = provider.createReEncryptionKey(
                      key.getSrcKeyName(), key.getDstKeyName());
                  if (kv == null) {
                    throw new KeyNotFoundException();
                  }
                  return kv;
                }
              });
    transformedEEKCache =
          CacheBuilder.newBuilder().expireAfterAccess(eekTimeoutMillis,
              TimeUnit.MILLISECONDS)
              .build();
  }

  @Override
  protected ReEncryptionKeyInstance createReEncryptionKey(String sourceEncryptionKeyName, String destinationEncryptionKeyName) {
    try {
      return reEncryptionKeyCache.get(
          new ReEncryptionKeyCacheKey(sourceEncryptionKeyName, destinationEncryptionKeyName));
    } catch (ExecutionException e)
    {
      e.printStackTrace(System.err);
    }
    return null;
  }
/* TODO findouf if possible to cache transforemd edeks
  @Override
  public EncryptedKeyVersion transformEncryptedKey(final EncryptedKeyVersion encryptedKeyVersion, final String destinationEncryptionKey) throws IOException, GeneralSecurityException {
    try {
      return transformedEEKCache.get(new EncryptedKeyCacheKey(
              new ReEncryptionKeyCacheKey(encryptedKeyVersion.getEncryptionKeyVersionName(),
                  destinationEncryptionKey),
              encryptedKeyVersion.getEncryptedKeyVersion().getVersionName()),
          new Callable<EncryptedKeyVersion>() {
            @Override
            public EncryptedKeyVersion call() throws Exception {
              final ReEncryptionKeyInstance reKey = createReEncryptionKey(
                  encryptedKeyVersion.getEncryptionKeyVersionName(), destinationEncryptionKey);
              return provider.transformEncryptedKey(encryptedKeyVersion, reKey);
            }
          }
      );
    } catch (ExecutionException e)
    {
      e.printStackTrace();
    }
    return null;
  }
*/
  @Override
  public void deleteReEncryptionKey(String srcName, String dstName) {
    reEncryptionKeyCache.invalidate(new ReEncryptionKeyCacheKey(srcName, dstName));
  }

  @SuppressWarnings("serial")
  private static class KeyNotFoundException extends Exception { }

  public String toString() {
    return getClass().getSimpleName() + ": " + provider.toString();
  }


}

