package com.nucypher.crypto.spec;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.spec.KeySpec;


public class KeyPairSpec implements KeySpec, Key {
  private byte[] publicKey;
  private byte[] secretKey;
  private String algorithm;

  public KeyPairSpec(byte[] publicKey, byte[] secretKey, String algorithm) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.algorithm = algorithm;
  }

  public KeyPairSpec(byte[] material, String algorithm)
    throws StreamCorruptedException {
    // TODO move this code to a separate class
    ByteBuffer buffer = ByteBuffer.wrap(material);
    int len = buffer.getInt();
    publicKey = new byte[len];
    len = buffer.getInt();
    secretKey = new byte[len];
    buffer.get(publicKey);
    buffer.get(secretKey);
    this.algorithm = algorithm;
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    // TODO move it to separate class
    int encodedSize = publicKey.length + secretKey.length + 2 * Integer.SIZE;
    ByteBuffer buffer = ByteBuffer.allocate(encodedSize);
    // writing header here
    buffer.putInt(publicKey.length);
    buffer.putInt(secretKey.length);
    buffer.put(publicKey);
    buffer.put(secretKey);
    if (buffer.hasArray())
      return null;
    return buffer.array();
  }

  public PrivateKeySpec getPrivate() {
    return new PrivateKeySpec(secretKey, getAlgorithm());
  }

  public PublicKeySpec getPublic() {
    return new PublicKeySpec(publicKey, getAlgorithm());
  }
}
