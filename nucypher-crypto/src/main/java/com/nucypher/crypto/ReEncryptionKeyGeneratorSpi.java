package com.nucypher.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public abstract class ReEncryptionKeyGeneratorSpi {

    public abstract void initialize(int keysize);

    public void initialize(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {
            throw new UnsupportedOperationException();
    }
    public abstract ReEncryptionKey generateReEncryptionKey(byte[] keyMaterialFrom, byte[] keyMaterialTo);
}
