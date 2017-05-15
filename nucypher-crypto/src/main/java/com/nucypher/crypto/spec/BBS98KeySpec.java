package com.nucypher.crypto.spec;

import org.apache.commons.codec.binary.Hex;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.Locale;

public class BBS98KeySpec implements KeySpec, PublicKey {
  private static final long serialVersionUID = 6577238317307289943L;

  private byte[] key;
  private byte[] G;
  private String algorithm;

  public BBS98KeySpec(byte[] encoded, String algorithm) {
    if(encoded != null && algorithm != null) {
      if(encoded.length == 0) {
        throw new IllegalArgumentException("Empty key");
      } else {
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        // readin header
        int keyLen = buffer.getInt();
        key = new byte[keyLen];
        int gLen = buffer.getInt();
        // reading body
        buffer.get(key);
        if(gLen > 0) {
          G = new byte[gLen];
          buffer.get(G);
        }
        this.algorithm = algorithm;
      }
    } else {
      throw new IllegalArgumentException("Missing argument");
    }
  }

  public BBS98KeySpec(byte[] material, byte[] g, String algorithm) {
    if(material != null && algorithm != null) {
      if(material.length == 0) {
        throw new IllegalArgumentException("Empty key");
      } else {
        this.key = (byte[])material.clone();
        this.algorithm = algorithm;
        if (g != null)
          this.G = (byte[])g.clone();
      }
    } else {
      throw new IllegalArgumentException("Missing argument");
    }
  }

  public BBS98KeySpec(byte[] material, byte[] g, int offset, int length, String algorithm) {
    if(material != null && algorithm != null) {
      if(material.length == 0) {
        throw new IllegalArgumentException("Empty key");
      } else if(material.length - offset < length) {
        throw new IllegalArgumentException("Invalid offset/length combination");
      } else if(length < 0) {
        throw new ArrayIndexOutOfBoundsException("len is negative");
      } else {
        this.key = new byte[length];
        System.arraycopy(material, offset, this.key, 0, length);
        this.algorithm = algorithm;
        if (g != null)
          this.G = (byte[])g.clone();
      }
    } else {
      throw new IllegalArgumentException("Missing argument");
    }
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public String getFormat() {
    return "WITH_G";
  }

  public byte[] getEncoded() {
    int gLen = (G != null ? G.length : 0);
    int encodedSize = key.length + gLen + 2 * Integer.SIZE;
    byte[] bufferBack = new byte[encodedSize];
    ByteBuffer buffer = ByteBuffer.wrap(bufferBack);
    // writing header
    buffer.putInt(key.length);
    buffer.putInt(gLen);
    // writing body
    buffer.put(key);
    if (G != null)
      buffer.put(G);
    return bufferBack;
  }

  public int hashCode() {
    int hashCode = 0;

    for(int i = 1; i < this.key.length; ++i) {
      hashCode += this.key[i] * i;
    }

    return hashCode ^ this.algorithm.toLowerCase(Locale.ENGLISH).hashCode();
  }

  public boolean equals(Object other) {
    if(this == other) {
      return true;
    } else if(!(other instanceof PrivateKey)) {
      return false;
    } else {
      String algorithm = ((PublicKey)other).getAlgorithm();
      if(algorithm.equalsIgnoreCase(this.algorithm)) {
        byte[] material = ((PublicKey)other).getEncoded();
        return MessageDigest.isEqual(this.key, material);
      } else {
        return false;
      }
    }
  }

  public byte[] getKeyMaterial()
  {
    return key;
  }

  public byte[] getParams()
  {
    return G;
  }
}
