package com.nucypher.crypto;

import com.nucypher.crypto.bbs98.WrapperBBS98;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Arrays;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.*;


public class WrapperBBS98Test {
  @BeforeClass
  public static void oneTimeSetUp() {
		Security.addProvider(new BouncyCastleProvider());

	}

  @Test
	public void testSimpleReEncryption() {
		SecureRandom sr = new SecureRandom(); // SecureRandom is thread-safe

		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");

		for (int i = 0; i < 1; i++) {
			byte[] message = new byte[16];
			sr.nextBytes(message);

      WrapperBBS98 pre = null;
			try {
        pre = new WrapperBBS98(ecSpec, sr);
			} catch (InvalidAlgorithmParameterException e)
			{
				Assert.assertTrue(e.getMessage(), false);
			}

			KeyPair pair = null;
      try {
        pair = pre.keygen();
      } catch (InvalidAlgorithmParameterException e)
      {
        Assert.assertTrue(e.getMessage(), false);
      }

			PublicKey pki = pair.getPublic();
			PrivateKey xi = pair.getPrivate();

			byte[] c = pre.encrypt(pki, message);

			byte[] m2 = pre.decrypt(xi, c);
//			System.out.println("m2 = " + BBS98BouncyCastle.bytesToHex(m2));

			if (!Arrays.areEqual(m2, message)) {
				System.out.println("Error 1!");
			}

      try {
        pair = pre.keygen();
      } catch (InvalidAlgorithmParameterException e)
      {
        Assert.assertTrue(e.getMessage(), false);
      }

			PublicKey pkj = pair.getPublic();
			PrivateKey xj = pair.getPrivate();

			//
			// // RKG & REENC
			//
			BigInteger rk = pre.rekeygen(xi, xj);

			byte[] c_j = pre.reencrypt(rk, c);

			byte[] m3 = pre.decrypt(xj, c_j);
//			System.out.println("m3 = " + BBS98BouncyCastle.bytesToHex(m2));

			if (!Arrays.areEqual(m3, message)) {
				System.out.println("Error 2!");
			}

		}
		System.out.println("End");
	}
}
