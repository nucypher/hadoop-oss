package com.nucypher.crypto.bbs98;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class WrapperBBS98 {

	private ECParameterSpec params;
	private SecureRandom random;

	// TODO: Right now this is fixed to P-256 points
	final static int COMPRESSED_ECPOINT_LENGTH = 33;

	public WrapperBBS98(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException
	{
		if (params instanceof ECGenParameterSpec)
			this.params = ECNamedCurveTable.getParameterSpec(((ECGenParameterSpec)params).getName());
		else if (params instanceof ECParameterSpec)
			this.params = (ECParameterSpec)params;
		else
			throw new InvalidAlgorithmParameterException();
		// TODO: check arguments
		this.random = random;
	}

	public KeyPair keygen() throws InvalidAlgorithmParameterException{
		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		kpg.initialize(params, random);
		return kpg.generateKeyPair();
	}
	
	public BigInteger rekeygen(PrivateKey pk_a, PrivateKey pk_b){
		BigInteger inv_sk_a = ((ECPrivateKey) pk_a).getD().modInverse(this.params.getN());
		BigInteger rk = ((ECPrivateKey) pk_b).getD().multiply(inv_sk_a).mod(this.params.getN());
		return rk;
	}

	public byte[] encrypt(PublicKey pk, byte[] message) {

		ECPoint m = encodeToECPoint(params, message, random);

		ECPoint[] c = BBS98BouncyCastle.encrypt(params, ((ECPublicKey) pk).getQ(), m, random);

		return encodeTuple(c);
	}

	public byte[] decrypt(PrivateKey sk, byte[] ciphertext) {
		ECPoint[] c = decodeTuple(ciphertext);

		ECPoint mPoint = BBS98BouncyCastle.decrypt(params, ((ECPrivateKey) sk).getD(), c);

		return decodeFromECPoint(this.params, mPoint);
	}

	public byte[] reencrypt(BigInteger rk, byte[] ciphertext) {

		ECPoint[] c = decodeTuple(ciphertext);

		ECPoint[] c_prime = BBS98BouncyCastle.reencrypt(params, rk, c);

		return encodeTuple(c_prime);
	}

	// TODO: Encoding to elliptic curve points is not implemented in BC
	private static ECPoint encodeToECPoint(ECParameterSpec ps, byte[] message, SecureRandom sr) {
		// Method based on Section 2.4 of https://eprint.iacr.org/2013/373.pdf

//		System.out.println("Encoding: " + BBS98BouncyCastle.bytesToHex(message));
		int lBits = ps.getN().bitLength() / 2;
//		System.out.println("N = " + ps.getN());
//		System.out.println("lbits: " + lBits);

		if (message.length * 8 > lBits) {
			throw new IllegalArgumentException("Message too large to be encoded");
		}

		BigInteger mask = BigInteger.ZERO.flipBit(lBits).subtract(BigInteger.ONE);
		BigInteger m = new BigInteger(1, message);

		ECFieldElement a = ps.getCurve().getA();
		ECFieldElement b = ps.getCurve().getB();

		BigInteger r;
		ECFieldElement x = null, y = null;
		do {
			r = BBS98BouncyCastle.getRandom(sr, ps.getN());
			r = r.andNot(mask).or(m);

			if (!ps.getCurve().isValidFieldElement(r)) {
				continue;
			}

			x = ps.getCurve().fromBigInteger(r);

			// y^2 = x^3 + ax + b = (x^2+a)x +b
			ECFieldElement y2 = x.square().add(a).multiply(x).add(b);
			y = y2.sqrt();

		} while (y == null);
		return ps.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());

	}

	// TODO: Encoding to elliptic curve points is not implemented in BC
	private static byte[] decodeFromECPoint(ECParameterSpec ps, ECPoint point) {
		// Method based on Section 2.4 of https://eprint.iacr.org/2013/373.pdf

		int lBits = ps.getN().bitLength() / 2;

		byte[] bs = new byte[lBits / 8];

		byte[] xbytes = point.normalize().getAffineXCoord().toBigInteger().toByteArray();

		System.arraycopy(xbytes, xbytes.length - bs.length, bs, 0, bs.length);
//		System.out.println("Decoded: " + BBS98BouncyCastle.bytesToHex(bs));
		return bs;
	}

	private ECPoint[] decodeTuple(byte[] tuple) {
		if (tuple.length != 2 * COMPRESSED_ECPOINT_LENGTH) {
			throw new IllegalArgumentException("Encoded tuple does not match expected size");
		}

		byte[] p1Bytes = new byte[COMPRESSED_ECPOINT_LENGTH];
		byte[] p2Bytes = new byte[COMPRESSED_ECPOINT_LENGTH];

		System.arraycopy(tuple, 0, p1Bytes, 0, COMPRESSED_ECPOINT_LENGTH);
		System.arraycopy(tuple, COMPRESSED_ECPOINT_LENGTH, p2Bytes, 0, COMPRESSED_ECPOINT_LENGTH);

		ECPoint p1 = params.getCurve().decodePoint(p1Bytes);
		ECPoint p2 = params.getCurve().decodePoint(p2Bytes);

		return new ECPoint[] { p1, p2 };
	}

	private byte[] encodeTuple(ECPoint[] tuple) {

		byte[] p1Bytes = tuple[0].getEncoded(true);
		byte[] p2Bytes = tuple[1].getEncoded(true);

		byte[] encoded = new byte[2 * COMPRESSED_ECPOINT_LENGTH];

		System.arraycopy(p1Bytes, 0, encoded, 0, COMPRESSED_ECPOINT_LENGTH);
		System.arraycopy(p2Bytes, 0, encoded, COMPRESSED_ECPOINT_LENGTH, COMPRESSED_ECPOINT_LENGTH);

		return encoded;
	}

	public ECParameterSpec getParams()
	{
		return params;
	}

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		SecureRandom sr = new SecureRandom(); // SecureRandom is thread-safe

		Security.addProvider(new BouncyCastleProvider());

		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");

		for (int i = 0; i < 1000; i++) {
			byte[] message = new byte[16];
			sr.nextBytes(message);

			// ECPoint point = encodeToECPoint(ecSpec, message, sr);
			// System.out.println(point);
			// byte[] res = decodeFromECPoint(ecSpec, point);

			BigInteger n = ecSpec.getN();

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");

			kpg.initialize(ecSpec, new SecureRandom());
			KeyPair pair = kpg.generateKeyPair();

			PublicKey pki = pair.getPublic();
			PrivateKey xi = pair.getPrivate();

			WrapperBBS98 pre = new WrapperBBS98(ecSpec, sr);

			byte[] c = pre.encrypt(pki, message);

			byte[] m2 = pre.decrypt(xi, c);
//			System.out.println("m2 = " + BBS98BouncyCastle.bytesToHex(m2));

			if (!Arrays.areEqual(m2, message)) {
				System.out.println("Error 1!");
			}

			pair = kpg.generateKeyPair();
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
