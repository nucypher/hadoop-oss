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

import com.nucypher.crypto.ReEncryptionKey;
import com.nucypher.crypto.generators.BBS98BCReEncryptionKeyGenerator;
import com.nucypher.crypto.spec.KeyPairSpec;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;

import org.apache.hadoop.crypto.key.*;
import org.bouncycastle.jce.interfaces.ECPrivateKey;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/**
 * A KeyProvider with Proxy Re-Encryption Extensions specifically for generating transformation keys
 *
 */
@InterfaceAudience.Public
@InterfaceStability.Unstable
public class KeyProviderProxyReEncryptionExtension extends
    KeyProviderCryptoExtension {

  public interface ProxyReEncryptionExtension extends KeyProviderCryptoExtension.CryptoExtension {

    /**
     * Generate re-encryption key from key, stored inside KMS, identified by <code>encryptionKeyName</code> to
     * key, provides in <code>destinationKey</code>. If current algorithm doesn't require private key to produce
     * re-encryption key - private key material in <code>destinationKey</code> is <code>null</code>
     *
     * @param encryptionKeyName - source key name to make re-encryption key from
     * @param destinationKey    - destination key material to make re-encryption key to
     * @return re-encryption key
     */
    byte[] generateReEncryptionKey(String encryptionKeyName, String destinationKeyVersionName, KeyPairMaterial destinationKey)
      throws IOException;

    /**
     * Same as {@link #generateReEncryptionKey(String encryptionKeyName, String destinationKeyVersionName, KeyPairMaterial destinationKey)}, but produce
     * re-encryption key between two key pairs, stored somewhere inside KMS
     *
     * @param encryptionKeyVersionName  - source key name to make re-encryption key from
     * @param destinationKeyVersionName - destination key name to make re-encryption key to
     * @return re-encryption key
     */
    byte[] generateReEncryptionKey(String encryptionKeyVersionName, String destinationKeyVersionName)
        throws IOException;
  }

  private static class DefaultProxyReEncryptionExtension  implements ProxyReEncryptionExtension {
    private final KeyProviderCryptoExtension provider;

    public DefaultProxyReEncryptionExtension(KeyProviderCryptoExtension provider) {
        this.provider = provider;
    }

    @Override
    public byte[] generateReEncryptionKey(String encryptionKeyName, String dstEncryptionKeyName, KeyPairMaterial destinationKey)
        throws IOException {
      BBS98BCReEncryptionKeyGenerator reEncryptionKeyGenerator =
          new BBS98BCReEncryptionKeyGenerator();
      KeyPairVersion srcKey = provider.getKeyPairVersion(encryptionKeyName);
      KeyPairSpec srcKeySpec = new KeyPairSpec(srcKey.getPublicMaterial().getMaterial(),
          srcKey.getPrivateMaterial().getMaterial(), reEncryptionKeyGenerator.getAlgorithm());
      KeyPairSpec dstKeySpec = new KeyPairSpec(destinationKey.getPublic(),
          destinationKey.getPrivate(), reEncryptionKeyGenerator.getAlgorithm());
      ECPrivateKey dstSk =
          SerializationUtils.deserialize(dstKeySpec.getPrivate().getKeyMaterial());
      try {
        reEncryptionKeyGenerator.initialize(dstSk.getParameters());
        ReEncryptionKey reKey = reEncryptionKeyGenerator.generateReEncryptionKey(
            srcKeySpec.getPrivate().getKeyMaterial(), dstKeySpec.getPrivate().getKeyMaterial());
        return reKey.getEncoded();
      } catch(InvalidAlgorithmParameterException e)
      {
        e.printStackTrace(System.err);
      }
      return null;
    }

    @Override
    public byte[] generateReEncryptionKey(String encryptionKeyVersionName, String destinationKeyVersionName)
        throws IOException   {
      KeyPairVersion dstKey = provider.getKeyPairVersion(destinationKeyVersionName);

      return generateReEncryptionKey(encryptionKeyVersionName, destinationKeyVersionName,
          new KeyPairMaterial(dstKey.getPublicMaterial().getMaterial(), dstKey.getPrivateMaterial().getMaterial()));
    }

    @Override
    public void warmUpEncryptedKeys(String... keyNames) throws IOException {
      provider.warmUpEncryptedKeys(keyNames);
    }

    @Override
    public void drain(String keyName) {
      // NO-OP since the default version does not cache any keys
    }

    @Override
    public EncryptedKeyVersion generateEncryptedKey(String encryptionKeyName) throws IOException, GeneralSecurityException {
      return provider.generateEncryptedKey(encryptionKeyName);
    }

    @Override
    public KeyVersion decryptEncryptedKey(EncryptedKeyVersion encryptedKeyVersion) throws IOException, GeneralSecurityException {
      return provider.decryptEncryptedKey(encryptedKeyVersion);
    }
  }

  public byte[] generateReEncryptionKey(String encryptionKeyName, String destinationKeyVersionName, KeyPairMaterial destinationKey)
      throws IOException {
    return getPREExtension().generateReEncryptionKey(encryptionKeyName, destinationKeyVersionName, destinationKey);
  }


  public byte[] generateReEncryptionKey(String encryptionKeyVersionName, String destinationKeyVersionName)
      throws IOException {
    return getPREExtension().generateReEncryptionKey(encryptionKeyVersionName, destinationKeyVersionName);
  }

  /**
   * This constructor is to be used by sub classes that provide
   * delegating/proxying functionality to the {@link ProxyReEncryptionExtension}
   * @param keyProvider
   * @param extension
   */
  protected KeyProviderProxyReEncryptionExtension(KeyPairProvider keyProvider,
      ProxyReEncryptionExtension extension) {
    super(keyProvider, extension);
  }

  protected ProxyReEncryptionExtension getPREExtension() {
    return (ProxyReEncryptionExtension)getExtension();
  }

  public static KeyProviderProxyReEncryptionExtension   createKeyProviderProxyReEncryptionExtension(
      KeyPairProvider keyProvider) {
    ProxyReEncryptionExtension proxyReEncryptionExtension = null;
    if (keyProvider instanceof ProxyReEncryptionExtension) {
      proxyReEncryptionExtension = (ProxyReEncryptionExtension) keyProvider;
    } else if (keyProvider instanceof KeyPairProviderExtension &&
        ((KeyPairProviderExtension)keyProvider).getKeyPairProvider() instanceof
            KeyProviderCryptoExtension.CryptoExtension) {
      KeyPairProviderExtension keyProviderExtension =
          (KeyPairProviderExtension)keyProvider;
      proxyReEncryptionExtension =
          (ProxyReEncryptionExtension)keyProviderExtension.getKeyPairProvider();
    } else {
      proxyReEncryptionExtension = new DefaultProxyReEncryptionExtension((KeyProviderCryptoExtension)keyProvider);
    }

    return new KeyProviderProxyReEncryptionExtension(keyProvider, proxyReEncryptionExtension);
  }


}
