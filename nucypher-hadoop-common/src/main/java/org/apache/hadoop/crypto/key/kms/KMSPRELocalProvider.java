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

package org.apache.hadoop.crypto.key.kms;

import com.google.common.base.Preconditions;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyPairProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.crypto.key.pre.KeyProviderProxyReEncryptionExtension;
import org.apache.hadoop.crypto.key.pre.ReEncryptionKeyProviderFactory;
import org.apache.hadoop.crypto.key.pre.ReEncryptionKeyProviderInterface;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;

@InterfaceAudience.Public
@InterfaceStability.Unstable
public class KMSPRELocalProvider extends KeyProviderProxyReEncryptionExtension {
  public static final String CONFIG_PREFIX = "hadoop.kms.";
  public static final String RE_KEY_PROVIDER_URI = CONFIG_PREFIX +
      "re.key.provider.uri";

  public static final String LOCAL_KMS_KEY_NAME_KEY = CONFIG_PREFIX +
      "local.key.name";
  public static final String LOCAL_KMS_KEY_NAME_DEFAULT =
      "local.kms.key";

  public static final String LOCAL_KMS_KEY_LOCAL_EDEK_GENERATION = CONFIG_PREFIX +
      "local.edek.generation";

  public static final boolean LOCAL_KMS_KEY_LOCAL_EDEK_GENERATION_KEY = false;

  final private static class LocalKeyProvider extends KeyPairProvider
  {
    private final KeyPairVersion localKeyVersion;
    private final Metadata localKeyMetatada;

    @Override
    public KeyPairVersion getKeyPairVersion(String versionName) throws IOException {
      return localKeyVersion;
    }

    @Override
    public List<KeyPairVersion> getKeyPairVersions(String name) throws IOException {
      return Collections.singletonList(localKeyVersion);
    }

    @Override
    public KeyPairVersion createKeyPair(String name, KeyPairMaterial material, Options options) throws IOException, NoSuchAlgorithmException {
      return localKeyVersion;
    }

    @Override
    public KeyPairVersion rollNewVersionPair(String name, KeyPairMaterial material) throws IOException {
      return localKeyVersion;
    }

    @Override
    public KeyVersion getKeyVersion(String versionName) throws IOException {
      return localKeyVersion.privateToKeyVersion();
    }

    @Override
    public List<String> getKeys() throws IOException {
      return Collections.singletonList(localKeyVersion.getName());
    }

    @Override
    public List<KeyVersion> getKeyVersions(String name) throws IOException {
      return Collections.singletonList(localKeyVersion.getPrivateMaterial());
    }

    @Override
    public Metadata getMetadata(String name) throws IOException {
      return localKeyMetatada;
    }

    @Override
    public KeyVersion createKey(String name, byte[] material, Options options) throws IOException {
      return localKeyVersion.privateToKeyVersion();
    }

    @Override
    public void deleteKey(String name) throws IOException {
      // NOPE do nothing
    }

    @Override
    public KeyVersion rollNewVersion(String name, byte[] material) throws IOException {
      return localKeyVersion.privateToKeyVersion();
    }

    @Override
    public void flush() throws IOException {

    }

    protected LocalKeyProvider(KeyPairVersion version, Metadata metadata, Configuration conf)
    {
      super(conf);
      localKeyVersion = version;
      localKeyMetatada = metadata;
    }
  }

  private static class ProxyReEncryptionExtension
      implements KeyProviderProxyReEncryptionExtension.ProxyReEncryptionExtension {

    private final KeyProviderCryptoExtension keyProvider;
    private final KeyProviderCryptoExtension localCryptoExtension;
    private final ReEncryptionKeyProviderInterface rekProvider;
    private final KeyPairVersion localKey;
    private final boolean localEDEKGeneration;


    public ProxyReEncryptionExtension(Configuration conf,
                                      KeyProviderCryptoExtension keyProvider)
        throws URISyntaxException, IOException, NoSuchAlgorithmException
    {
      this.keyProvider = keyProvider;

      final String keyName = conf.get(LOCAL_KMS_KEY_NAME_KEY, LOCAL_KMS_KEY_NAME_DEFAULT);

      final Metadata meta = keyProvider.getMetadata(keyName);

      if (meta == null) {
        localKey = keyProvider.createKeyPair(keyName, new Options(conf));
      } else {
        localKey = keyProvider.rollNewVersionPair(keyName);
      }

      localEDEKGeneration = conf.getBoolean(LOCAL_KMS_KEY_LOCAL_EDEK_GENERATION, LOCAL_KMS_KEY_LOCAL_EDEK_GENERATION_KEY);

      Metadata metadata = keyProvider.getMetadata(localKey.getName());

      localCryptoExtension = KeyProviderCryptoExtension.createKeyProviderCryptoExtension(
          new LocalKeyProvider(localKey, metadata, conf)
      );

      final String renString = conf.get(RE_KEY_PROVIDER_URI);
      final String renUrlStringList[] = renString.split(",");

      if (renUrlStringList.length == 0)
        throw new IOException("Invalid " + RE_KEY_PROVIDER_URI);

      int index = renUrlStringList.length < 2  ? 0 : new SecureRandom().nextInt(renUrlStringList.length);

      final URI renURI = new URI(renUrlStringList[index]);

      this.rekProvider = ReEncryptionKeyProviderFactory.get(renURI, conf);

    }

    @Override
    public byte[] generateReEncryptionKey(String encryptionKeyName, String destinationKeyVersionName, KeyPairMaterial destinationKey)
      throws IOException
    {
      throw new IllegalArgumentException("generateReEncryptionKey cannot be used with current provider extension");
    }

    @Override
    public byte[] generateReEncryptionKey(String encryptionKeyVersionName, String destinationKeyVersionName)
        throws IOException
    {
      throw new IllegalArgumentException("generateReEncryptionKey cannot be used with current provider extension");
    }

    @Override
    public void warmUpEncryptedKeys(String... keyNames) throws IOException {
      // NO-OP since the default version does not cache any keys
    }

    @Override
    public void drain(String keyName) {
      // NO-OP since the default version does not cache any keys
    }

    @Override
    public EncryptedKeyVersion generateEncryptedKey(String encryptionKeyName) throws IOException, GeneralSecurityException {
      if (localEDEKGeneration) {
        final EncryptedKeyVersion localEDEK = keyProvider.generateEncryptedKey(localKey.getName());
        final KeyPairVersion encryptionKey = keyProvider.getCurrentKeyPair(encryptionKeyName);
        Preconditions.checkNotNull(encryptionKey,
            "KeyVersion name '%s' does not exist", encryptionKeyName);
        return rekProvider.transformEncryptedKey(localEDEK, encryptionKey.getVersionName());
      } else {
        return keyProvider.generateEncryptedKey(encryptionKeyName);
      }
    }

    @Override
    public KeyVersion decryptEncryptedKey(EncryptedKeyVersion encryptedKeyVersion) throws IOException, GeneralSecurityException {
      final EncryptedKeyVersion newEDEK = rekProvider.transformEncryptedKey(encryptedKeyVersion, localKey.getVersionName());
      return localCryptoExtension.decryptEncryptedKey(newEDEK);
    }
  }

  @Override
  public byte[] generateReEncryptionKey(String encryptionKeyName, String destinationKeyVersionName, KeyPairMaterial destinationKey) throws IOException {
    throw new IOException("KMSPRELocalProvider doesn't support re-encryption key generatio");
  }

  @Override
  public byte[] generateReEncryptionKey(String encryptionKeyVersionName, String destinationKeyVersionName) throws IOException {
    throw new IOException("KMSPRELocalProvider doesn't support re-encryption key generatio");
  }

  public KMSPRELocalProvider(Configuration conf,
                             KeyProviderCryptoExtension keyProviderProxyReEncryptionExtension)
      throws IOException, URISyntaxException, NoSuchAlgorithmException
  {
    super(keyProviderProxyReEncryptionExtension,
        new ProxyReEncryptionExtension(conf, keyProviderProxyReEncryptionExtension));
  }
}
