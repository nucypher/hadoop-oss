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
package org.apache.hadoop.crypto;

import com.nucypher.crypto.ReEncryptionKey;
import com.nucypher.crypto.generators.BBS98BCKeyPairGenerator;
import com.nucypher.crypto.generators.BBS98BCReEncryptionKeyGenerator;
import com.nucypher.crypto.spec.KeyPairSpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.junit.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_CRYPTO_CIPHER_SUITE_KEY;
import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_KEY_PREFIX;

public class TestBBS98BCCryptoCodec {
  private static final Log LOG = LogFactory.getLog(TestBBS98BCCryptoCodec.class);

  private Configuration conf = new Configuration();
  private Configuration reEncConf = new Configuration();

  private KeyPairSpec key;
  private KeyPairSpec key2;
  private ReEncryptionKey reKey;

  @Before
  public void setUp() throws IOException {
    BBS98BCKeyPairGenerator bbs98KeyPairGenerator = new BBS98BCKeyPairGenerator();
    bbs98KeyPairGenerator.initialize(256, new SecureRandom());
    KeyPair keyPair = bbs98KeyPairGenerator.generateKeyPair();
    key = new KeyPairSpec(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded(), "BBS98");
    KeyPair keyPair2 = bbs98KeyPairGenerator.generateKeyPair();
    key2 = new KeyPairSpec(keyPair2.getPublic().getEncoded(), keyPair2.getPrivate().getEncoded(), "BBS98");

    BBS98BCReEncryptionKeyGenerator reEncryptionKeyGenerator =
        new BBS98BCReEncryptionKeyGenerator();
    reEncryptionKeyGenerator.initialize(256);
    reKey = reEncryptionKeyGenerator.generateReEncryptionKey(
        key.getPrivate().getKeyMaterial(), key2.getPrivate().getKeyMaterial());

    conf.set(HADOOP_SECURITY_CRYPTO_CIPHER_SUITE_KEY, CipherSuite.BBS98_PADDING.getName());
    conf.set(HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_KEY_PREFIX + CipherSuite.BBS98_PADDING.getConfigSuffix(),
        BBS98BCCryptoCodec.class.getName());

    reEncConf.set(HADOOP_SECURITY_CRYPTO_CIPHER_SUITE_KEY, CipherSuite.BBS98RE_NOPADDING.getName());
    reEncConf.set(HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_KEY_PREFIX + CipherSuite.BBS98RE_NOPADDING.getConfigSuffix(),
        BBS98BCTransformationCryptoCodec.class.getName());
  }

  @Test(timeout = 120000)
  public void testBBS98BCCryptoCodecEncryptDecrypt() throws Exception {
    CryptoCodec encCodec = CryptoCodec.getInstance(conf);
    Assert.assertNotNull(encCodec);

    byte[] data = new byte[16];
    byte[] encrypted = null;
    byte[] decryptedData = null;
    SecureRandom random = new SecureRandom();
    random.nextBytes(data);
    final byte[] iv = new byte[16];
    random.nextBytes(iv);

    System.out.println("data: " + Hex.encodeHexString(data));
    {
      Encryptor encryptor = encCodec.createEncryptor();
      Assert.assertTrue(encryptor != null);
      encryptor.init(key.getPublic().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(data.length);
      input.put(data);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(100);
      int bytesWritten = 0;
      encryptor.encrypt(input, output);
      encrypted = new byte[output.limit()];
      output.rewind();
      output.get(encrypted);
      System.out.println("encrypted: " + Hex.encodeHexString(encrypted));

    }
    {
      Decryptor decryptor = encCodec.createDecryptor();
      Assert.assertTrue(decryptor != null);

      decryptor.init(key.getPrivate().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(encrypted.length);
      input.put(encrypted);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(30);
      int bytesRead = 0;
      decryptor.decrypt(input, output);
      decryptedData = new byte[data.length];
      output.rewind();
      output.get(decryptedData);
      System.out.println("decryptedData: " + Hex.encodeHexString(decryptedData));
    }
    Assert.assertArrayEquals(data, decryptedData);
  }

  @Test(timeout = 120000)
  public void testBBS98BCCryptoCodecEncryptReEncryptDecrypt() throws Exception {

    CryptoCodec encCodec = CryptoCodec.getInstance(conf);
    Assert.assertNotNull(encCodec);

    CryptoCodec reEncCodec = CryptoCodec.getInstance(reEncConf);
    Assert.assertNotNull(reEncCodec);

    byte[] data = new byte[16];
    byte[] encrypted = null;
    byte[] reEncrypted = null;
    byte[] decryptedData = null;
    SecureRandom random = new SecureRandom();
    random.nextBytes(data);
    final byte[] iv = new byte[16];
    random.nextBytes(iv);

    System.out.println("data: " + Hex.encodeHexString(data));
    {
      Encryptor encryptor = encCodec.createEncryptor();
      Assert.assertTrue(encryptor != null);
      encryptor.init(key.getPublic().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(data.length);
      input.put(data);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(100);
      encryptor.encrypt(input, output);
      encrypted = new byte[output.limit()];
      output.rewind();
      output.get(encrypted);
      System.out.println("encrypted: " + Hex.encodeHexString(encrypted));

    }
    {
      Encryptor encryptor = reEncCodec.createEncryptor();
      Assert.assertTrue(encryptor != null);
      encryptor.init(reKey.getEncoded(), null);

      ByteBuffer input = ByteBuffer.allocateDirect(encrypted.length);
      input.put(encrypted);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(encrypted.length);
      encryptor.encrypt(input, output);
      reEncrypted = new byte[output.limit()];
      output.rewind();
      output.get(reEncrypted);
      System.out.println("re-encrypted: " + Hex.encodeHexString(reEncrypted));
    }
    {
      Decryptor decryptor = encCodec.createDecryptor();
      Assert.assertTrue(decryptor != null);

      decryptor.init(key2.getPrivate().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(reEncrypted.length);
      input.put(reEncrypted);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(30);
      decryptor.decrypt(input, output);
      decryptedData = new byte[data.length];
      output.rewind();
      output.get(decryptedData);
      System.out.println("decryptedData: " + Hex.encodeHexString(decryptedData));
    }
    Assert.assertArrayEquals(data, decryptedData);
  }
}
