package com.nucypher.crypto.spec;

import org.apache.commons.lang3.SerializationUtils;

import java.security.PublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

public class PublicKeySpec extends BBS98KeySpec implements PublicKey {
  private static final long serialVersionUID = 6577238317307289922L;

  public PublicKeySpec(byte[] encoded, String algorithm) {
   super(encoded, algorithm);
  }

  public PublicKeySpec(byte[] material, byte[] g, String algorithm) {
    super(material, g, algorithm);
  }

  public PublicKeySpec(byte[] material, byte[] g, int offset, int length, String algorithm) {
    super(material, g, offset, length, algorithm);
  }

  public PublicKeySpec(ECPublicKey key, String algorithm)
  {
    super(SerializationUtils.serialize(key), null, algorithm);
  }
}
