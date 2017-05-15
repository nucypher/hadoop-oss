package com.nucypher.crypto;

import java.math.BigInteger;
import java.security.Key;

public interface ReEncryptionKey extends Key {
  BigInteger getValue();
}