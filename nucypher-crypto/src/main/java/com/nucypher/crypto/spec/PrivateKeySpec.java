package com.nucypher.crypto.spec;

import org.apache.commons.lang3.SerializationUtils;
import org.bouncycastle.jce.interfaces.ECPrivateKey;

import java.security.PrivateKey;

public class PrivateKeySpec extends BBS98KeySpec implements  PrivateKey {
  private static final long serialVersionUID = 6577238317307289911L;

  public PrivateKeySpec(byte[] encoded, String algorithm) {
    super(encoded, algorithm);
  }
  public PrivateKeySpec(byte[] material, byte[] g, String algorithm) {
    super(material, g, algorithm);
  }

  public PrivateKeySpec(byte[] material,  byte[] g, int offset, int length, String algorithm) {
    super(material, g, offset, length, algorithm);
  }

  public PrivateKeySpec(ECPrivateKey key, String algorithm)
  {
    super(SerializationUtils.serialize(key), null, algorithm);
  }
}
