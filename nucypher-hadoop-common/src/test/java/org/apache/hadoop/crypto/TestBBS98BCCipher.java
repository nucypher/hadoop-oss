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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

public class TestBBS98BCCipher {
  private KeyPairSpec key;
  private KeyPairSpec key2;
  private ReEncryptionKey reKey;
  private AlgorithmParameterSpec params;

  @BeforeClass
  public static void classSetUp()
  {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Before
  public void setUp() {
    BBS98BCKeyPairGenerator bbs98KeyPairGenerator = new BBS98BCKeyPairGenerator();
    bbs98KeyPairGenerator.initialize(256, new SecureRandom());
    params = bbs98KeyPairGenerator.getParams();
    KeyPair keyPair = bbs98KeyPairGenerator.generateKeyPair();
    key = new KeyPairSpec(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded(), "BBS98");
    KeyPair keyPair2 = bbs98KeyPairGenerator.generateKeyPair();
    key2 = new KeyPairSpec(keyPair2.getPublic().getEncoded(), keyPair2.getPrivate().getEncoded(), "BBS98");

    BBS98BCReEncryptionKeyGenerator reEncryptionKeyGenerator =
        new BBS98BCReEncryptionKeyGenerator();
    reEncryptionKeyGenerator.initialize(256);
    reKey = reEncryptionKeyGenerator.generateReEncryptionKey(
        key.getPrivate().getKeyMaterial(), key2.getPrivate().getKeyMaterial());
  }

  @Test
  public void testGetInstance() throws Exception {
    BBS98BCCipher cipher = BBS98BCCipher.getInstance("BBS98/None/Padding");
    Assert.assertTrue(cipher != null);
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    byte[] data = new byte[16];
    byte[] encrypted = null;
    byte[] decryptedData = null;
    SecureRandom random = new SecureRandom();
    random.nextBytes(data);
    final byte[] iv = new byte[16];
    random.nextBytes(iv);

    System.out.println("data: " + Hex.encodeHexString(data));
    {
      BBS98BCCipher cipher = BBS98BCCipher.getInstance("BBS98/None/Padding");
      Assert.assertTrue(cipher != null);
      cipher.init(BBS98BCCipher.ENCRYPT_MODE, key.getPublic().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(data.length);
      input.put(data);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(100);
      int bytesWritten = 0;
      bytesWritten = cipher.update(input, output);
      Assert.assertNotEquals(bytesWritten, 0);
      encrypted = new byte[bytesWritten];
      output.rewind();
      output.get(encrypted, 0, bytesWritten);
      System.out.println("encrypted: " + Hex.encodeHexString(encrypted));

    }
    {
      BBS98BCCipher cipher = BBS98BCCipher.getInstance("BBS98/None/Padding");
      Assert.assertTrue(cipher != null);

      cipher.init(BBS98BCCipher.DECRYPT_MODE, key.getPrivate().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(encrypted.length);
      input.put(encrypted);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(30);
      int bytesRead = 0;
      bytesRead = cipher.update(input, output);
      Assert.assertNotEquals(bytesRead, 0);
      decryptedData = new byte[data.length];
      output.rewind();
      output.get(decryptedData);
      System.out.println("decryptedData: " + Hex.encodeHexString(decryptedData));
    }
    Assert.assertArrayEquals(data, decryptedData);
  }

  @Test
  public void testReEncryptDecrypt() throws Exception {
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
      BBS98BCCipher cipher = BBS98BCCipher.getInstance("BBS98/None/Padding");
      Assert.assertTrue(cipher != null);
      cipher.init(BBS98BCCipher.ENCRYPT_MODE, key.getPublic().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(data.length);
      input.put(data);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(100);
      int bytesWritten = 0;
      bytesWritten = cipher.update(input, output);
      Assert.assertNotEquals(bytesWritten, 0);
      encrypted = new byte[bytesWritten];
      output.rewind();
      output.get(encrypted, 0, bytesWritten);
      System.out.println("encrypted: " + Hex.encodeHexString(encrypted));

    }
    {
      BBS98BCCipher cipher = BBS98BCCipher.getInstance("BBS98/None/Padding");
      Assert.assertTrue(cipher != null);
      cipher.init(BBS98BCCipher.TRANSFORM_MODE, reKey.getEncoded(), iv, params);

      ByteBuffer input = ByteBuffer.allocateDirect(encrypted.length);
      input.put(encrypted);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(encrypted.length);
      int bytesWritten = 0;
      bytesWritten = cipher.update(input, output);
      Assert.assertNotEquals(bytesWritten, 0);
      reEncrypted = new byte[bytesWritten];
      output.rewind();
      output.get(reEncrypted, 0, bytesWritten);
      System.out.println("encrypted: " + Hex.encodeHexString(reEncrypted));
    }
    {
      BBS98BCCipher cipher = BBS98BCCipher.getInstance("BBS98/None/Padding");
      Assert.assertTrue(cipher != null);

      cipher.init(BBS98BCCipher.DECRYPT_MODE, key2.getPrivate().getEncoded(), iv);

      ByteBuffer input = ByteBuffer.allocateDirect(reEncrypted.length);
      input.put(reEncrypted);
      input.rewind();
      ByteBuffer output = ByteBuffer.allocateDirect(30);
      int bytesRead = 0;
      bytesRead = cipher.update(input, output);
      Assert.assertNotEquals(bytesRead, 0);
      decryptedData = new byte[data.length];
      output.rewind();
      output.get(decryptedData);
      System.out.println("decryptedData: " + Hex.encodeHexString(decryptedData));
    }
    Assert.assertArrayEquals(data, decryptedData);
  }


  }
