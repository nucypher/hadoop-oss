package com.nucypher.crypto;

import com.nucypher.crypto.generators.BBS98BCKeyPairGenerator;
import com.nucypher.crypto.spec.PrivateKeySpec;
import com.nucypher.crypto.spec.PublicKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

public class BBS98BCKeyPairGeneratorTest {
  @BeforeClass
  public static void oneTimeSetUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testSimpleReEncryption() {

    BBS98BCKeyPairGenerator bbs98KeyPairGenerator = new BBS98BCKeyPairGenerator();
    bbs98KeyPairGenerator.initialize(256, null);

    KeyPair keyPair = bbs98KeyPairGenerator.generateKeyPair();
    Map<String, String> keypair = new HashMap<>();
    PublicKeySpec publicKey = (PublicKeySpec)keyPair.getPublic();
    PrivateKeySpec  privateKey = (PrivateKeySpec)keyPair.getPrivate();

    System.out.println("private key size " + privateKey.getKeyMaterial().length +
    " g size " + (privateKey.getParams() != null ? privateKey.getParams().length : 0) + " encoded " + privateKey.getEncoded().length);
    System.out.println("public key size " + publicKey.getKeyMaterial().length +
        " g size " + (publicKey.getParams() != null ? publicKey.getParams().length : 0) + " encoded " + publicKey.getEncoded().length);
    keypair.put("pk", Hex.encodeHexString(keyPair.getPublic().getEncoded()));
    keypair.put("sk", Hex.encodeHexString(keyPair.getPrivate().getEncoded()));
    String pk = keypair.get("pk");
    String sk = keypair.get("sk");
    System.out.println("##pk:"+pk);
    System.out.println("##sk:"+sk);

/*
    String message = "hello, good morning";

    Map<String, String> cipher = engine.encrypt(g, pk, message);
    System.out.println("##cipher c1:"+cipher.get("c1"));
    System.out.println("##cipher c2:"+cipher.get("c2"));

    String m = engine.decrypt(g, sk, cipher);
    System.out.println("##decrypted text:"+m);
    Assert.assertEquals("##Decrypted failed",  m, message);

    System.out.println("##Decrypted successful");


    Map<String, String> keypair2 = engine.generateKey(g);
    String pk2 = keypair2.get("pk");
    String sk2 = keypair2.get("sk");
    System.out.println("##pk2:"+pk2);
    System.out.println("##sk2:"+sk2);

    String rk = engine.rekeygen(g, sk, sk2);
    System.out.println("##rk:"+rk);

    Map<String, String> reCipher = engine.reEncrypt(g, rk, cipher);
    System.out.println("##recipher c1:"+reCipher.get("c1"));
    System.out.println("##recipher c2:"+reCipher.get("c2"));

    String m1 = engine.decrypt(g, sk2, reCipher);
    System.out.println("##decrypted re-encrypted text:"+m1);
    Assert.assertEquals("##ReEncrypted failed",  m, m1);
    System.out.println("##ReEncrypted cipher decrypted successful");
*/
  }
}
