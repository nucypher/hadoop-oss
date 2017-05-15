package com.nucypher.crypto.generators;

import com.nucypher.crypto.ReEncryptionKey;
import com.nucypher.crypto.ReEncryptionKeyGeneratorSpi;
import com.nucypher.crypto.bbs98.WrapperBBS98;
import com.nucypher.crypto.spec.BBS98ReEncryptionKeySpec;
import org.apache.commons.lang3.SerializationUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Integers;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Hashtable;

public class BBS98BCReEncryptionKeyGenerator extends ReEncryptionKeyGeneratorSpi {
  private WrapperBBS98 engine = null;

  private static Hashtable ecParameters = new Hashtable();

  public BBS98BCReEncryptionKeyGenerator() {
  }

  @Override
  public void initialize(int keysize)
  {
     ECParameterSpec generationParam = ECNamedCurveTable.getParameterSpec("P-256");
    // Enable this code when we will have separate codec parameters for data and keys
   // ECGenParameterSpec generationParam = (ECGenParameterSpec)ecParameters.get(Integers.valueOf(keysize));
    //System.err.print("got params name " + generationParam.getName());
    try {
      initialize(generationParam);
    } catch (InvalidAlgorithmParameterException e)
    {
      e.printStackTrace();
    }
  }

  @Override
  public void initialize(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    engine = new WrapperBBS98(params, null);
  }

  @Override
  public ReEncryptionKey generateReEncryptionKey(byte[] keyMaterialFrom, byte[] keyMaterialTo) {
    final PrivateKey keyFrom = SerializationUtils.deserialize(keyMaterialFrom);
    final PrivateKey keyTo = SerializationUtils.deserialize(keyMaterialTo);
    return new BBS98ReEncryptionKeySpec(
        engine.rekeygen(keyFrom, keyTo));
  }

  static {
    Security.addProvider(new BouncyCastleProvider());

    ecParameters.put(Integers.valueOf(192), new ECGenParameterSpec("prime192v1"));
    ecParameters.put(Integers.valueOf(239), new ECGenParameterSpec("prime239v1"));
   // ecParameters.put(Integers.valueOf(256), new ECGenParameterSpec("prime256v1"));
    ecParameters.put(Integers.valueOf(256), new ECGenParameterSpec("P-256"));
    ecParameters.put(Integers.valueOf(224), new ECGenParameterSpec("P-224"));
    ecParameters.put(Integers.valueOf(384), new ECGenParameterSpec("P-384"));
    ecParameters.put(Integers.valueOf(521), new ECGenParameterSpec("P-521"));
  }

  public String getAlgorithm() {
    return "BBS98";
  }
}
