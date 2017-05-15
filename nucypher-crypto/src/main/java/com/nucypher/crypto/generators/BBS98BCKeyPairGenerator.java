package com.nucypher.crypto.generators;

import com.nucypher.crypto.bbs98.WrapperBBS98;
import com.nucypher.crypto.spec.PrivateKeySpec;
import com.nucypher.crypto.spec.PublicKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Integers;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Hashtable;

public class BBS98BCKeyPairGenerator extends KeyPairGeneratorSpi {
  private WrapperBBS98 engine = null;

  private static Hashtable ecParameters = new Hashtable();

  public BBS98BCKeyPairGenerator() {
  }

  @Override
  public void initialize(int keysize, SecureRandom random)
  {

     ECParameterSpec generationParam = ECNamedCurveTable.getParameterSpec("P-256");
    // Enable this code when we will have separate codec parameters for data and keys
   // ECGenParameterSpec generationParam = (ECGenParameterSpec)ecParameters.get(Integers.valueOf(keysize));
    //System.err.print("got params name " + generationParam.getName());
    try {
      initialize(generationParam, random);
    } catch (InvalidAlgorithmParameterException e)
    {
      e.printStackTrace();
    }
  }

  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    engine = new WrapperBBS98(params, random);
  }

  @Override
  public KeyPair generateKeyPair() {
    try {
      KeyPair keyPair =  engine.keygen();
     /* System.err.println("got public: " + keyPair.getPublic().getClass().toString() +
                         " and private " + keyPair.getPrivate().getClass().toString());*/

      return new KeyPair(
          new PublicKeySpec(
              (ECPublicKey)keyPair.getPublic(), getAlgorithm()),
          new PrivateKeySpec(
              (ECPrivateKey)keyPair.getPrivate(), getAlgorithm()));
    } catch (InvalidAlgorithmParameterException e)
    {
      e.printStackTrace(System.err);
    }
    return null;
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

  public AlgorithmParameterSpec getParams() { return engine.getParams(); }
}
