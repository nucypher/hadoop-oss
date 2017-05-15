package org.apache.hadoop.crypto;

import com.google.common.base.Preconditions;
import com.nucypher.crypto.ReEncryptionKey;
import com.nucypher.crypto.bbs98.WrapperBBS98;
import com.nucypher.crypto.spec.BBS98KeySpec;
import com.nucypher.crypto.spec.BBS98ReEncryptionKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.SerializationUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.io.serializer.Serialization;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.StringTokenizer;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_KEY_PREFIX;

public class BBS98BCCipher {
  private static final Log LOG =
      LogFactory.getLog(BBS98BCCipher.class.getName());

  public static final String HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_BBS98_NONE_PADDING_CURVE_KEY =
      HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_KEY_PREFIX
          + CipherSuite.BBS98_PADDING.getConfigSuffix() + "curve";
  public static final String HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_BBS98_NONE_PADDING_CURVE_DEFAULT =
      "P-256";

  public static final int TRANSFORM_MODE = 2;
  public static final int ENCRYPT_MODE = 1;
  public static final int DECRYPT_MODE = 0;

  private static final int ENCRYPTED_BLOCK_SIZE = 33;

  private WrapperBBS98 engine = null;
  AlgorithmParameterSpec params;
  private int mode;
  private ECKey key;
  private ReEncryptionKey reKey;
  private int blockSize;
  private byte[] iv;
  SecureRandom random = new SecureRandom();

  BBS98BCCipher() {
  }

  public void init(int mode, byte[] key, byte[] iv) {
    init(mode, key, iv, null);
  }

  public void init(int mode, byte[] key, byte[] iv, AlgorithmParameterSpec params) {
    Preconditions.checkNotNull(key);

    this.mode = mode;
    try {
      if (mode == TRANSFORM_MODE)
      {
        reKey = new BBS98ReEncryptionKeySpec(key);
        this.params = params;
      } else {
        Preconditions.checkNotNull(iv);
        BBS98KeySpec keySpec = new BBS98KeySpec(key, "BBS98");
        this.blockSize = 30;
        this.key = (ECKey) SerializationUtils.deserialize(keySpec.getKeyMaterial());
        this.params = this.key.getParameters();
      }
      engine = new WrapperBBS98(this.params, random);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    }

    this.iv = iv;
  }

  public int update(ByteBuffer input, ByteBuffer output)
      throws ShortBufferException {
      //checkState();
      Preconditions.checkArgument(input.isDirect() && output.isDirect(),
           "Direct buffers are required.");
      try {
        int outputPosition = output.position();
        if (mode == TRANSFORM_MODE)
          transform(input, output);
        else if (mode == ENCRYPT_MODE)
          encrypt(input, output);
        else
          decrypt(input, output);
        return output.position() - outputPosition;
      } catch (IOException e) {
        e.printStackTrace();
      }
      return 0;
  }

  public int doFinal(ByteBuffer output) throws ShortBufferException,
      IllegalBlockSizeException, BadPaddingException {
    return 0;
  }

  private void transform(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    // TODO push it into utility
    // TODO split on pieces here
    int len = inBuffer.limit();
    byte[] message = new byte[len];
    inBuffer.get(message, 0, len);
    // System.err.print("engine " + engine + " key " + reKey);
    byte[] bytes = engine.reencrypt(reKey.getValue(), message);
    outBuffer.put(bytes);
    outBuffer.flip();
  }

  private void decrypt(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    // TODO push it into utility
    // TODO split on pieces here
    byte[] bytes = new byte[ENCRYPTED_BLOCK_SIZE * 2];
    inBuffer.get(bytes);
    PrivateKey sk  = (PrivateKey)key;
    byte[] decrypted = engine.decrypt(sk, bytes);
    for (int i = 0; i < iv.length; i++) {
      decrypted[i] = (byte) (iv[i] ^ decrypted[i]);
    }
    outBuffer.put(decrypted);
    outBuffer.flip();
  }

  private void encrypt(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    // TODO split on pieces here
    int len = inBuffer.limit();
    byte[] message = new byte[len];
    inBuffer.get(message, 0, len);

    // System.err.println("iv size " + iv.length + " msg size " + message.length);

    for (int i = 0; i < iv.length; i++) {
      message[i] = (byte) (iv[i] ^ message[i]);
    }

    PublicKey pk = (PublicKey)key;

    byte[] cipher = engine.encrypt(pk, message);

    outBuffer.put(cipher);
    outBuffer.flip();
  }

  public static final BBS98BCCipher getInstance(String transformation)
      throws NoSuchAlgorithmException, NoSuchPaddingException {

    return new BBS98BCCipher();
  }

  private static byte[] getBytes(String str)
      throws DecoderException
  {
    return Base64.decodeBase64(Hex.decodeHex(str.toCharArray()));
  }

  private static String getString(byte[] bytes)
      throws DecoderException
  {
    return Hex.encodeHexString(Base64.encodeBase64(bytes));
  }

  /** Nested class for algorithm, mode and padding. */
  private static class Transform {
    final String alg;
    final String mode;
    final String padding;

    public Transform(String alg, String mode, String padding) {
      this.alg = alg;
      this.mode = mode;
      this.padding = padding;
    }
  }

  private static Transform tokenizeTransformation(String transformation)
      throws NoSuchAlgorithmException {
    if (transformation == null) {
      throw new NoSuchAlgorithmException("No transformation given.");
    }

    /*
     * Array containing the components of a Cipher transformation:
     *
     * index 0: algorithm (e.g., AES)
     * index 1: mode (e.g., CTR)
     * index 2: padding (e.g., NoPadding)
     */
    String[] parts = new String[3];
    int count = 0;
    StringTokenizer parser = new StringTokenizer(transformation, "/");
    while (parser.hasMoreTokens() && count < 3) {
      parts[count++] = parser.nextToken().trim();
    }
    if (count != 3 || parser.hasMoreTokens()) {
      throw new NoSuchAlgorithmException("Invalid transformation format: " +
          transformation);
    }
    return new Transform(parts[0], parts[1], parts[2]);
  }
}
