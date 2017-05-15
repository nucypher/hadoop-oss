/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.crypto.key.pre;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.CipherSuite;
import org.apache.hadoop.crypto.CryptoCodec;
import org.apache.hadoop.crypto.Encryptor;
import org.apache.hadoop.crypto.key.KeyPairProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EncryptedKeyVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

public abstract class AbstractReEncryptionKeyProvider implements ReEncryptionKeyProviderInterface, Configurable {

    public static final String CONFIG_PREFIX = "hadoop.ren.";

    public static final String HADOOP_SECURITY_CRYPTO_RE_ENC_SUITE_KEY =
        CONFIG_PREFIX + "re.enc.suite";
    public static final String HADOOP_SECURITY_CRYPTO_RE_ENC_SUITE_DEFAULT =
        "BBS98RE/None/NoPadding";

    // Property to Enable/Disable Caching
    public static final String RE_KEY_CACHE_ENABLE = CONFIG_PREFIX +
        "cache.enable";
    // Timeout for the Key and Metadata Cache
    public static final String RE_KEY_CACHE_TIMEOUT_KEY = CONFIG_PREFIX +
        "cache.timeout.ms";

    public static final boolean RE_KEY_CACHE_ENABLE_DEFAULT = true;
    // 10 mins
    public static final long RE_KEY_CACHE_TIMEOUT_DEFAULT = 10 * 60 * 1000;

    private static Logger LOG =
        LoggerFactory.getLogger(AbstractReEncryptionKeyProvider.class);

    private CipherSuite suite;

    private Configuration conf;


    protected abstract ReEncryptionKeyInstance createReEncryptionKey(String sourceEncryptionKeyName, String destinationEncryptionKeyName);

    public EncryptedKeyVersion transformEncryptedKey(EncryptedKeyVersion encryptedKeyVersion, ReEncryptionKeyInstance reKey)
        throws IOException, GeneralSecurityException
    {
        CryptoCodec reCC = CryptoCodec.getInstance(conf, suite);
        Encryptor encryptor = reCC.createEncryptor();
        encryptor.init(reKey.getMaterial(), null);
        int keyLen = encryptedKeyVersion.getEncryptedKeyVersion().getMaterial().length;
        ByteBuffer bbIn = ByteBuffer.allocateDirect(keyLen);
        ByteBuffer bbOut = ByteBuffer.allocateDirect(keyLen);
        bbIn.put(encryptedKeyVersion.getEncryptedKeyVersion().getMaterial());
        bbIn.flip();
        encryptor.encrypt(bbIn, bbOut);
        byte[] encryptedKey = new byte[bbOut.limit()];
        bbOut.get(encryptedKey);
        final String dstKeyNameVersion = reKey.getDstNameVersion();
        return EncryptedKeyVersion.createForDecryption(KeyPairProvider.getBaseName(dstKeyNameVersion),
            dstKeyNameVersion,
            encryptedKeyVersion.getEncryptedKeyIv(), encryptedKey);
    }

    @Override
    public EncryptedKeyVersion transformEncryptedKey(EncryptedKeyVersion encryptedKeyVersion, String destinationEncryptionKey)
        throws IOException, GeneralSecurityException
    {
        ReEncryptionKeyInstance reKey = createReEncryptionKey(encryptedKeyVersion.getEncryptionKeyVersionName(),
                destinationEncryptionKey);
        return transformEncryptedKey(encryptedKeyVersion, reKey);
    }

    @Override
    public void deleteReEncryptionKey(String srcName, String dstName)
    {
        // NOOP
        //reEncryptionKeys.remove(ReEncryptionKeyProviderInterface.ReEncryptionKeyInstance.
        //    getReEncryptionKeyName(srcName, dstName));
    }

    AbstractReEncryptionKeyProvider(Configuration conf)
    {
        setConf(conf);
    }

    @Override
    public void setConf(Configuration conf) {
        String reEncryptionSuite = conf.get(HADOOP_SECURITY_CRYPTO_RE_ENC_SUITE_KEY,
            HADOOP_SECURITY_CRYPTO_RE_ENC_SUITE_DEFAULT);
        suite = CipherSuite.convert(reEncryptionSuite);
        this.conf = conf;
    }

    @Override
    public Configuration getConf() {
        return conf;
    }

}