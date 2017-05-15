package org.apache.hadoop.crypto.key;
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

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.List;


import com.nucypher.crypto.generators.BBS98BCKeyPairGenerator;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;

/**
 * A KeyProvider with support for KeyPairs
 *
 */
@InterfaceAudience.Public
@InterfaceStability.Unstable
public abstract class KeyPairProvider extends KeyProvider {

  public static class KeyPairMaterial
  {
    private final byte[] publicMaterial;
    private final byte[] privateMaterial;

    public KeyPairMaterial(byte[] publicMaterial, byte[] privateMaterial)
    {
      this.publicMaterial = publicMaterial;
      this.privateMaterial = privateMaterial;
    }

    public byte[] getPublic()
    {
      return publicMaterial;
    }

    public byte[] getPrivate()
    {
      return privateMaterial;
    }
  }

  public static class KeyPairVersion {
    private final String name;
    private final String versionName;
    private final KeyPairMaterial material;

    protected KeyPairVersion(String name, String versionName,
                             KeyPairMaterial material) {
      this.name = name;
      this.versionName = versionName;
      this.material = material;
    }

    public String getName() {
      return name;
    }

    public String getVersionName() {
      return versionName;
    }

    public KeyVersion getPublicMaterial() {
      return new KeyVersion(name, versionName, material.getPublic());
    }

    public KeyVersion getPrivateMaterial() {
      return new KeyVersion(name, versionName, material.getPrivate());
    }

    public String toString() {
      StringBuilder buf = new StringBuilder();
      buf.append("key(");
      buf.append(versionName);
      buf.append(")=");
      if (material == null) {
        buf.append("null");
      } else {
        buf.append("public:");
        for(byte b: material.getPublic()) {
          buf.append(' ');
          int right = b & 0xff;
          if (right < 0x10) {
            buf.append('0');
          }
          buf.append(Integer.toHexString(right));
        }
        buf.append(";private::");
        for(byte b: material.getPrivate()) {
          buf.append(' ');
          int right = b & 0xff;
          if (right < 0x10) {
            buf.append('0');
          }
          buf.append(Integer.toHexString(right));
        }
      }
      return buf.toString();
    }
    public KeyVersion privateToKeyVersion()
    {
      return new KeyVersion(name, versionName, material == null ? null : material.getPrivate());
    }
    public KeyVersion publicToKeyVersion()
    {
      return new KeyVersion(name, versionName, material == null ? null : material.getPublic());
    }
  }
  /**
   * Get the key material for a specific version of the key. This method is used
   * when decrypting data.
   * @param versionName the name of a specific version of the key
   * @return the key material
   * @throws IOException
   */
  public abstract KeyPairVersion getKeyPairVersion(String versionName
  ) throws IOException;

  /**
   * Get the key material for all versions of a specific key name.
   * @return the list of key material
   * @throws IOException
   */
  public abstract List<KeyPairVersion> getKeyPairVersions(String name) throws IOException;
  /**
   * Get the current version of the key, which should be used for encrypting new
   * data.
   * @param versionName the base name of the key
   * @return the version name of the current version of the key or null if the
   *    key version doesn't exist
   * @throws IOException
   */
  public KeyPairVersion getCurrentKeyPair(String versionName)
      throws IOException  {
    Metadata meta = getMetadata(versionName);
    if (meta == null) {
      return null;
    }
    return getKeyPairVersion(buildVersionName(versionName, meta.getVersions() - 1));
  }

  /**
   * Generate public/private key pair material
   * @param size of private key to be generated
   * @param algorithm - algorithm to be used for generation
   * @return generated key pair material
   * @throws NoSuchAlgorithmException
   */
  protected  KeyPairMaterial generateKeyPair(int size, String algorithm)
      throws NoSuchAlgorithmException
  {
 /* TODO temporaly replace this with concrete algorithm, because we need to sing our  jar to use it as generators
    algorithm = getAlgorithm(algorithm);
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
    keyGenerator.initialize(size);
    KeyPair key = keyGenerator.generateKeyPair();
    return new KeyPairMaterial(key.getPublic().getEncoded(), key.getPrivate().getEncoded());
    */
    /*
    BBS98KeyPairGenerator keyPairGenerator = new BBS98KeyPairGenerator();
        */
    BBS98BCKeyPairGenerator keyPairGenerator = new BBS98BCKeyPairGenerator();
    keyPairGenerator.initialize(size, null);
    KeyPair key = keyPairGenerator.generateKeyPair();
    return new KeyPairMaterial(key.getPublic().getEncoded(), key.getPrivate().getEncoded());
  }

  public abstract KeyPairVersion createKeyPair(String name, KeyPairMaterial material,
                                               Options options) throws IOException, NoSuchAlgorithmException;

  /**
   * Generate key pair, identified by <code>name</code>
   * @param name name of key to be generated and stored
   * @param options - generation options
   * @return - version of generated key pair
   * @throws NoSuchAlgorithmException
   * @throws IOException
   */
  public KeyPairVersion createKeyPair(String name, Options options)
      throws IOException, NoSuchAlgorithmException  {
    KeyPairMaterial material = generateKeyPair(options.getBitLength(), options.getCipher());
    return createKeyPair(name, material, options);
  }

  public KeyVersion createKey(String name, Options options)
      throws NoSuchAlgorithmException, IOException {
    KeyPairMaterial material = generateKeyPair(options.getBitLength(), options.getCipher());
    return createKeyPair(name, material, options).privateToKeyVersion();
  }

  /** Roll a new version of the given key.
   * @param name the basename of the key
   * @param material the new key material
   * @return the name of the new version of the key
   * @throws IOException
   */
  public abstract KeyPairVersion rollNewVersionPair(String name, KeyPairMaterial material) throws IOException;

  /**
   * Roll a new version of the given key generating the material for it.
   * <p/>
   * This implementation generates the key material and calls the
   * {@link #rollNewVersion(String, byte[])} method.
   *
   * @param name the basename of the key
   * @return the name of the new version of the key
   * @throws IOException
   */
  public KeyPairVersion rollNewVersionPair(String name) throws NoSuchAlgorithmException,
      IOException {
    Metadata meta = getMetadata(name);
    KeyPairMaterial material = generateKeyPair(meta.getBitLength(), meta.getCipher());
    return rollNewVersionPair(name, material);
  }

  public KeyVersion rollNewVersion(String name) throws NoSuchAlgorithmException,
      IOException {
    KeyPairVersion version = rollNewVersionPair(name);
    return version.privateToKeyVersion();
  }
  /**
   * Constructor.
   *
   * @param conf configuration for the generators
   */
  protected KeyPairProvider(Configuration conf) {
    super(conf);
  }

  @Override
  public void close() throws IOException {
  }

  /**
   * Get the algorithm from the cipher.
   *
   * @return the algorithm name
   */
  private String getAlgorithm(String cipher) {
    int slash = cipher.indexOf('/');
    if (slash == -1) {
      return cipher;
    } else {
      return cipher.substring(0, slash);
    }
  }

}

