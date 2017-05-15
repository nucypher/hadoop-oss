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
package org.apache.hadoop.crypto.key.kms.server;

import com.codahale.metrics.JmxReporter;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.*;
import org.apache.hadoop.crypto.key.kms.KMSPRELocalProvider;
import org.apache.hadoop.crypto.key.pre.*;
import org.apache.hadoop.http.HttpServer2;
import org.apache.hadoop.security.authorize.AccessControlList;
import org.apache.hadoop.util.VersionInfo;
import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import java.io.File;
import java.net.URI;
import java.net.URL;

@InterfaceAudience.Private
public class KMSWebApp implements ServletContextListener {

  private static final String LOG4J_PROPERTIES = "kms-log4j.properties";

  private static final String METRICS_PREFIX = "hadoop.kms.";
  private static final String ADMIN_CALLS_METER = METRICS_PREFIX +
      "admin.calls.meter";
  private static final String KEY_CALLS_METER = METRICS_PREFIX +
      "key.calls.meter";
  private static final String INVALID_CALLS_METER = METRICS_PREFIX +
      "invalid.calls.meter";
  private static final String UNAUTHORIZED_CALLS_METER = METRICS_PREFIX +
      "unauthorized.calls.meter";
  private static final String UNAUTHENTICATED_CALLS_METER = METRICS_PREFIX +
      "unauthenticated.calls.meter";
  private static final String GENERATE_EEK_METER = METRICS_PREFIX +
      "generate_eek.calls.meter";
  private static final String DECRYPT_EEK_METER = METRICS_PREFIX +
      "decrypt_eek.calls.meter";
  private static final String TRANSFORM_EEK_METER = METRICS_PREFIX +
      "transform_eek.calls.meter";

  private static Logger LOG;
  private static MetricRegistry metricRegistry;

  private JmxReporter jmxReporter;
  private static Configuration kmsConf;
  private static KMSACLs kmsAcls;
  private static Meter adminCallsMeter;
  private static Meter keyCallsMeter;
  private static Meter unauthorizedCallsMeter;
  private static Meter unauthenticatedCallsMeter;
  private static Meter decryptEEKCallsMeter;
  private static Meter generateEEKCallsMeter;
  private static Meter transformEEKCalMeter;

  private static Meter invalidCallsMeter;
  private static KMSAudit kmsAudit;
  private static RENAudit renAudit;
  private static KeyProviderProxyReEncryptionExtension keyProviderProxyReEncryptionExtension;
  private static AbstractReEncryptionKeyProvider reEncryptionKeyProvider;

  static {
    SLF4JBridgeHandler.removeHandlersForRootLogger();
    SLF4JBridgeHandler.install();
  }

  private void initLogging(String confDir) {
    if (System.getProperty("log4j.configuration") == null) {
      System.setProperty("log4j.defaultInitOverride", "true");
      boolean fromClasspath = true;
      File log4jConf = new File(confDir, LOG4J_PROPERTIES).getAbsoluteFile();
      if (log4jConf.exists()) {
        PropertyConfigurator.configureAndWatch(log4jConf.getPath(), 1000);
        fromClasspath = false;
      } else {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        URL log4jUrl = cl.getResource(LOG4J_PROPERTIES);
        if (log4jUrl != null) {
          PropertyConfigurator.configure(log4jUrl);
        }
      }
      LOG = LoggerFactory.getLogger(KMSWebApp.class);
      LOG.debug("KMS log starting");
      if (fromClasspath) {
        LOG.warn("Log4j configuration file '{}' not found", LOG4J_PROPERTIES);
        LOG.warn("Logging with INFO level to standard output");
      }
    } else {
      LOG = LoggerFactory.getLogger(KMSWebApp.class);
    }
  }

  @Override
  public void contextInitialized(ServletContextEvent sce) {
    try {
      String confDir = System.getProperty(KMSConfiguration.KMS_CONFIG_DIR);
      if (confDir == null) {
        throw new RuntimeException("System property '" +
            KMSConfiguration.KMS_CONFIG_DIR + "' not defined");
      }
      kmsConf = KMSConfiguration.getKMSConf();
      initLogging(confDir);
      LOG.info("-------------------------------------------------------------");
      LOG.info("  Java runtime version : {}", System.getProperty(
          "java.runtime.version"));
      LOG.info("  User: {}", System.getProperty("user.name"));
      LOG.info("  KMS Hadoop Version: " + VersionInfo.getVersion());
      LOG.info("-------------------------------------------------------------");

      kmsAcls = new KMSACLs();
      kmsAcls.startReloader();

      metricRegistry = new MetricRegistry();
      jmxReporter = JmxReporter.forRegistry(metricRegistry).build();
      jmxReporter.start();
      generateEEKCallsMeter = metricRegistry.register(GENERATE_EEK_METER,
          new Meter());
      decryptEEKCallsMeter = metricRegistry.register(DECRYPT_EEK_METER,
          new Meter());
      transformEEKCalMeter = metricRegistry.register(TRANSFORM_EEK_METER,
          new Meter());
      adminCallsMeter = metricRegistry.register(ADMIN_CALLS_METER, new Meter());
      keyCallsMeter = metricRegistry.register(KEY_CALLS_METER, new Meter());
      invalidCallsMeter = metricRegistry.register(INVALID_CALLS_METER,
          new Meter());
      unauthorizedCallsMeter = metricRegistry.register(UNAUTHORIZED_CALLS_METER,
          new Meter());
      unauthenticatedCallsMeter = metricRegistry.register(
          UNAUTHENTICATED_CALLS_METER, new Meter());

      kmsAudit =
          new KMSAudit(kmsConf.getLong(
              KMSConfiguration.KMS_AUDIT_AGGREGATION_WINDOW,
              KMSConfiguration.KMS_AUDIT_AGGREGATION_WINDOW_DEFAULT));

      // this is required for the the JMXJsonServlet to work properly.
      // the JMXJsonServlet is behind the authentication filter,
      // thus the '*' ACL.
      sce.getServletContext().setAttribute(HttpServer2.CONF_CONTEXT_ATTRIBUTE,
          kmsConf);
      sce.getServletContext().setAttribute(HttpServer2.ADMINS_ACL,
          new AccessControlList(AccessControlList.WILDCARD_ACL_VALUE));


      KMSConfiguration.Mode mode = KMSConfiguration.Mode.convert(
          kmsConf.get(KMSConfiguration.KMS_MODE_KEY, KMSConfiguration.KMS_MODE_DEFAULT));

      // intializing the KeyProvider
      String providerString = kmsConf.get(KMSConfiguration.KEY_PROVIDER_URI);
      if (providerString == null) {
        throw new IllegalStateException("No KeyProvider has been defined");
      }

      URI providerURI = new URI(providerString);

      LOG.info("Initialing Key Provider " + providerURI.toString());

      KeyPairProvider keyProvider = (KeyPairProvider) KeyProviderFactory.get(providerURI, kmsConf);

      LOG.info("Initialized KeyProvider " + keyProvider + " in " + mode.toString() + " mode");

       //Make caching provider compatible with KeyPairProvider
      if (kmsConf.getBoolean(KMSConfiguration.KEY_CACHE_ENABLE,
          KMSConfiguration.KEY_CACHE_ENABLE_DEFAULT)) {
        long keyTimeOutMillis =
            kmsConf.getLong(KMSConfiguration.KEY_CACHE_TIMEOUT_KEY,
                KMSConfiguration.KEY_CACHE_TIMEOUT_DEFAULT);
        long currKeyTimeOutMillis =
            kmsConf.getLong(KMSConfiguration.CURR_KEY_CACHE_TIMEOUT_KEY,
                KMSConfiguration.CURR_KEY_CACHE_TIMEOUT_DEFAULT);
        keyProvider = new CachingKeyProvider(keyProvider, keyTimeOutMillis,
            currKeyTimeOutMillis);
      }

      if (mode == KMSConfiguration.Mode.GLOBAL_KMS) {
        KeyProviderCryptoExtension keyProviderCryptoExtension = KeyProviderCryptoExtension.
            createKeyProviderCryptoExtension(keyProvider);
        keyProviderCryptoExtension =
            new EagerKeyGeneratorKeyProviderCryptoExtension(kmsConf,
                keyProviderCryptoExtension);
        keyProviderProxyReEncryptionExtension =
            KeyProviderProxyReEncryptionExtension.
                createKeyProviderProxyReEncryptionExtension(keyProviderCryptoExtension);
      } else if (mode == KMSConfiguration.Mode.LOCAL_KMS) {
        KeyProviderCryptoExtension keyProviderCryptoExtension = KeyProviderCryptoExtension.
            createKeyProviderCryptoExtension(keyProvider);
        keyProviderProxyReEncryptionExtension = new KMSPRELocalProvider(kmsConf, keyProviderCryptoExtension);
      } else { // KMSConfiguration.Mode.RE_NODE
        renAudit = new RENAudit(kmsConf.getLong(
            KMSConfiguration.KMS_AUDIT_AGGREGATION_WINDOW,
            KMSConfiguration.KMS_AUDIT_AGGREGATION_WINDOW_DEFAULT));

        String reProviderString = kmsConf.get(KMSPRELocalProvider.RE_KEY_PROVIDER_URI);
        if (reProviderString == null) {
          throw new IllegalStateException("No ReEncryptionKeyProvider has been defined");
        }

        URI reProviderURI = new URI(reProviderString);
        LOG.info("Initialing Key Provider " + reProviderURI.toString());
        //KeyProviderCryptoExtension keyProviderCryptoExtension = KeyProviderCryptoExtension.
        //    createKeyProviderCryptoExtension(keyProvider);
        keyProviderProxyReEncryptionExtension =
            KeyProviderProxyReEncryptionExtension.
                createKeyProviderProxyReEncryptionExtension(keyProvider);

        reEncryptionKeyProvider = ReEncryptionKeyProvider.createReEncryptionKeyProvider(
            keyProviderProxyReEncryptionExtension, kmsConf);

        if (kmsConf.getBoolean(AbstractReEncryptionKeyProvider.RE_KEY_CACHE_ENABLE,
            AbstractReEncryptionKeyProvider.RE_KEY_CACHE_ENABLE_DEFAULT)) {
          long reKeyTimeOutMillis =
              kmsConf.getLong(AbstractReEncryptionKeyProvider.RE_KEY_CACHE_TIMEOUT_KEY,
                  AbstractReEncryptionKeyProvider.RE_KEY_CACHE_TIMEOUT_DEFAULT);
          reEncryptionKeyProvider =
              new CachingReEncryptionKeyProvider(
                  reEncryptionKeyProvider, reKeyTimeOutMillis, 0);
        }

        LOG.info("Initialized KeyProviderProxyReEncryptionExtension "
            + reEncryptionKeyProvider);
        LOG.info("REN Started");
        return;
      }

      if (kmsConf.getBoolean(KMSConfiguration.KEY_AUTHORIZATION_ENABLE,
          KMSConfiguration.KEY_AUTHORIZATION_ENABLE_DEFAULT)) {
        keyProviderProxyReEncryptionExtension =
            new KeyAuthorizationKeyProvider(
                keyProviderProxyReEncryptionExtension, kmsAcls);
      }
        
      LOG.info("Initialized KeyProviderProxyReEncryptionExtension "
          + keyProviderProxyReEncryptionExtension);
      final int defaultBitlength = kmsConf
          .getInt(KeyProvider.DEFAULT_BITLENGTH_NAME,
              KeyProvider.DEFAULT_BITLENGTH);
      LOG.info("Default key bitlength is {}", defaultBitlength);
      LOG.info("KMS Started");
    } catch (Throwable ex) {
      System.out.println();
      System.out.println("ERROR: Hadoop KMS could not be started");
      System.out.println();
      System.out.println("REASON: " + ex.toString());
      System.out.println();
      System.out.println("Stacktrace:");
      System.out.println("---------------------------------------------------");
      ex.printStackTrace(System.out);
      System.out.println("---------------------------------------------------");
      System.out.println();
      System.exit(1);
    }
  }

  @Override
  public void contextDestroyed(ServletContextEvent sce) {
    kmsAudit.shutdown();
    kmsAcls.stopReloader();
    jmxReporter.stop();
    jmxReporter.close();
    metricRegistry = null;
    LOG.info("KMS Stopped");
  }

  public static Configuration getConfiguration() {
    return new Configuration(kmsConf);
  }

  public static KMSACLs getACLs() {
    return kmsAcls;
  }

  public static Meter getAdminCallsMeter() {
    return adminCallsMeter;
  }

  public static Meter getKeyCallsMeter() {
    return keyCallsMeter;
  }

  public static Meter getInvalidCallsMeter() {
    return invalidCallsMeter;
  }

  public static Meter getGenerateEEKCallsMeter() {
    return generateEEKCallsMeter;
  }

  public static Meter getDecryptEEKCallsMeter() {
    return decryptEEKCallsMeter;
  }

  public static Meter getTransformEEKCallsMeter() {
    return transformEEKCalMeter;
  }

  public static Meter getUnauthorizedCallsMeter() {
    return unauthorizedCallsMeter;
  }

  public static Meter getUnauthenticatedCallsMeter() {
    return unauthenticatedCallsMeter;
  }

  public static KeyProviderProxyReEncryptionExtension getKeyProvider() {
    return keyProviderProxyReEncryptionExtension;
  }

  public static ReEncryptionKeyProviderInterface getReEncryptionKeyProvider() {
    return reEncryptionKeyProvider;
  }

  public static KMSAudit getKMSAudit() {
    return kmsAudit;
  }

  public static RENAudit getRENAudit() {
    return renAudit;
  }
}
