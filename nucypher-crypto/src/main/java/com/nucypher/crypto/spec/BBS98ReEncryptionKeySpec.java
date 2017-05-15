package com.nucypher.crypto.spec;

import com.nucypher.crypto.ReEncryptionKey;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class BBS98ReEncryptionKeySpec implements KeySpec, ReEncryptionKey {
  private static final long serialVersionUID = 6577238317304289941L;

  private BigInteger rk;
  @Override
  public String getAlgorithm() {
    return "BBS98";
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    return rk.toByteArray();
  }

  public BBS98ReEncryptionKeySpec(BigInteger rk)
  {
    this.rk = rk;
  }

  public BBS98ReEncryptionKeySpec(byte[] encoded)
  {
    this.rk = new BigInteger(encoded);
  }

  @Override
  public BigInteger getValue()
  {
    return rk;
  }
}
