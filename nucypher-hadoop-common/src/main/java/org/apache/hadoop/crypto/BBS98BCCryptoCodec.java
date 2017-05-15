package org.apache.hadoop.crypto;

import com.google.common.base.Preconditions;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;


public class BBS98BCCryptoCodec extends CryptoCodec {
  private static final Log LOG =
      LogFactory.getLog(BBS98BCCryptoCodec.class.getName());

  protected static final CipherSuite SUITE = CipherSuite.BBS98_PADDING;

  private static final int BBS98_BLOCK_SIZE = SUITE.getAlgorithmBlockSize();

  private Configuration conf;

  private SecureRandom random;

  @Override
  public CipherSuite getCipherSuite() {
    return SUITE;
  }


  @Override
  public Encryptor createEncryptor() throws GeneralSecurityException {
    return new BBS98BCCipherInternal(BBS98BCCipher.ENCRYPT_MODE);

  }

  @Override
  public Decryptor createDecryptor() throws GeneralSecurityException {
    return new BBS98BCCipherInternal(BBS98BCCipher.DECRYPT_MODE);
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
    // TODO put initialisation here
    random = new SecureRandom();
  }

  @Override
  public Configuration getConf() {
    return  conf;
  }

  private static class BBS98BCCipherInternal implements Encryptor, Decryptor {
    private final BBS98BCCipher cipher;
    private final int mode;
    private boolean contextReset = false;

    public BBS98BCCipherInternal(int mode) throws GeneralSecurityException {
      this.mode = mode;
      cipher = BBS98BCCipher.getInstance(SUITE.getName());
    }

    @Override
    public void init(byte[] key, byte[] iv) throws IOException {
      Preconditions.checkNotNull(key);
      Preconditions.checkNotNull(iv);
      contextReset = false;
      cipher.init(mode, key, iv);
    }

    @Override
    public void encrypt(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      process(inBuffer, outBuffer);
    }

    @Override
    public void decrypt(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      process(inBuffer, outBuffer);
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
