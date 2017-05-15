package org.apache.hadoop.crypto;

import com.google.common.base.Preconditions;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;


public class BBS98BCTransformationCryptoCodec extends CryptoCodec {
  private static final Log LOG =
      LogFactory.getLog(BBS98BCTransformationCryptoCodec.class.getName());

  protected static final CipherSuite SUITE = CipherSuite.BBS98RE_NOPADDING;

  private static final int BBS98_BLOCK_SIZE = SUITE.getAlgorithmBlockSize();

  private Configuration conf;

  private SecureRandom random;

  private AlgorithmParameterSpec params;

  @Override
  public CipherSuite getCipherSuite() {
    return SUITE;
  }


  @Override
  public Encryptor createEncryptor() throws GeneralSecurityException {
    return new BBS98BCTransformationCipherInternal(params);

  }

  @Override
  public Decryptor createDecryptor() throws GeneralSecurityException {
    throw new IllegalArgumentException("Decryptor is now used for transformation");
  }

  @Override
  public void calculateIV(byte[] initIV, long counter, byte[] IV) {
      // TODO not used here?
  }

  @Override
  public void generateSecureRandom(byte[] bytes) {
    random.nextBytes(bytes);
  }

  @Override
  public void setConf(Configuration conf) {
    String curveName = conf.get(BBS98BCCipher.HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_BBS98_NONE_PADDING_CURVE_KEY,
        BBS98BCCipher.HADOOP_SECURITY_CRYPTO_CODEC_CLASSES_BBS98_NONE_PADDING_CURVE_DEFAULT);

    params = new ECGenParameterSpec(curveName);
    random = new SecureRandom();

    this.conf = conf;
  }

  @Override
  public Configuration getConf() {
    return  conf;
  }

  private static class BBS98BCTransformationCipherInternal implements Encryptor, Decryptor {
    private final BBS98BCCipher cipher;
    private boolean contextReset = false;
    private AlgorithmParameterSpec params;


    public BBS98BCTransformationCipherInternal(AlgorithmParameterSpec params) throws GeneralSecurityException {
      this.params = params;
      cipher = BBS98BCCipher.getInstance(SUITE.getName());
    }

    @Override
    public void init(byte[] key, byte[] iv) throws IOException {
      Preconditions.checkNotNull(key);
      contextReset = false;
      cipher.init(BBS98BCCipher.TRANSFORM_MODE, key, iv, params);
    }

    @Override
    public void encrypt(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      process(inBuffer, outBuffer);
    }

    @Override
    public void decrypt(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      throw new IllegalArgumentException("Cannot use decrypt method in transformation mode");
    }

    private void process(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      try {
        int inputSize = inBuffer.remaining();
        int n = cipher.update(inBuffer, outBuffer);
        if (n < inputSize) {
          /**
           * Typically code will not get here. OpensslCipher#update will
           * consume all input data and put result in outBuffer.
           * OpensslCipher#doFinal will reset the crypto context.
           */
          contextReset = true;
          cipher.doFinal(outBuffer);
        }
      } catch (Exception e) {
        throw new IOException(e);
      }
    }

    @Override
    public boolean isContextReset() {
      return contextReset;
    }
  }
}
