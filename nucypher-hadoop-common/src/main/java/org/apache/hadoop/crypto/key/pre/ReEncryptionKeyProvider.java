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
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EncryptedKeyVersion;
import org.apache.hadoop.crypto.key.KeyProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;

public class ReEncryptionKeyProvider extends AbstractReEncryptionKeyProvider{

    public static final String SCHEME_NAME = "memren";

    private KeyProviderProxyReEncryptionExtension keyProvider;

    protected ReEncryptionKeyInstance createReEncryptionKey(String sourceEncryptionKeyName, String destinationEncryptionKeyName) {
        try {
            final byte[] material = keyProvider.generateReEncryptionKey(sourceEncryptionKeyName,
                destinationEncryptionKeyName);

           return new ReEncryptionKeyInstance(sourceEncryptionKeyName,
               destinationEncryptionKeyName, material);
        } catch (IOException e)
        {
            e.printStackTrace(System.err);
        }
        return null;
    }

    private ReEncryptionKeyProvider(KeyProviderProxyReEncryptionExtension keyProvider,
                                    Configuration conf)
    {
        super(conf);
        this.keyProvider = keyProvider;
    }

    public static ReEncryptionKeyProvider createReEncryptionKeyProvider(
        KeyProviderProxyReEncryptionExtension keyProvider, Configuration conf)
    {
        return new ReEncryptionKeyProvider(keyProvider, conf);
    }

}