package com.nucypher.hadoop.hdfs;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.nucypher.hadoop.hdfs.protocol.NuCypherExtClientProtocol;
import com.nucypher.hadoop.hdfs.protocolPB.NuCypherExtClientNamenodeProtocolPB;
import com.nucypher.hadoop.hdfs.protocolPB.NuCypherExtClientNamenodeProtocolTranslatorPB;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.HAUtilClient;
import org.apache.hadoop.hdfs.NameNodeProxies;
import org.apache.hadoop.hdfs.client.HdfsClientConfigKeys;
import org.apache.hadoop.hdfs.client.impl.DfsClientConf;
import org.apache.hadoop.hdfs.protocol.HdfsConstants;
import org.apache.hadoop.hdfs.server.namenode.ha.AbstractNNFailoverProxyProvider;
import org.apache.hadoop.hdfs.server.namenode.ha.WrappedFailoverProxyProvider;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.retry.*;
import org.apache.hadoop.ipc.ProtobufRpcEngine;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Create proxy objects with {@link NuCypherExtClientProtocol} to communicate with a remote
 * NN. Generally use {@link NuCypherExtNameNodeProxiesClient#createProxyWithNuCypherExtClientProtocol(
 * Configuration, URI, AtomicBoolean)}, which will create either an HA- or
 * non-HA-enabled client proxy as appropriate.
 *
 * For creating proxy objects with other protocols, please see
 * {@link NameNodeProxies#createProxy(Configuration, URI, Class)}.
 */
@InterfaceAudience.Private
public class NuCypherExtNameNodeProxiesClient {

  private static final Logger LOG = LoggerFactory.getLogger(
      NuCypherExtNameNodeProxiesClient.class);

  /**
   * Wrapper for a client proxy as well as its associated service ID.
   * This is simply used as a tuple-like return type for created NN proxy.
   */
  public static class ProxyAndInfo<PROXYTYPE> {
    private final PROXYTYPE proxy;
    private final Text dtService;
    private final InetSocketAddress address;

    public ProxyAndInfo(PROXYTYPE proxy, Text dtService,
                        InetSocketAddress address) {
      this.proxy = proxy;
      this.dtService = dtService;
      this.address = address;
    }

    public PROXYTYPE getProxy() {
      return proxy;
    }

    public Text getDelegationTokenService() {
      return dtService;
    }

    public InetSocketAddress getAddress() {
      return address;
    }
  }

  /**
   * Creates the namenode proxy with the ClientProtocol. This will handle
   * creation of either HA- or non-HA-enabled proxy objects, depending upon
   * if the provided URI is a configured logical URI.
   *
   * @param conf the configuration containing the required IPC
   *        properties, client failover configurations, etc.
   * @param nameNodeUri the URI pointing either to a specific NameNode
   *        or to a logical nameservice.
   * @param fallbackToSimpleAuth set to true or false during calls to indicate
   *        if a secure client falls back to simple auth
   * @return an object containing both the proxy and the associated
   *         delegation token service it corresponds to
   * @throws IOException if there is an error creating the proxy
   * @see {@link NameNodeProxies#createProxy(Configuration, URI, Class)}.
   */
  public static ProxyAndInfo<NuCypherExtClientProtocol> createProxyWithNuCypherExtClientProtocol(
      Configuration conf, URI nameNodeUri, AtomicBoolean fallbackToSimpleAuth)
      throws IOException {
    AbstractNNFailoverProxyProvider<NuCypherExtClientProtocol> failoverProxyProvider =
        createFailoverProxyProvider(conf, nameNodeUri, NuCypherExtClientProtocol.class,
            true, fallbackToSimpleAuth);

    if (failoverProxyProvider == null) {
      InetSocketAddress nnAddr = NuCypherExtUtilClient.getNNAddress(nameNodeUri);
      Text dtService = SecurityUtil.buildTokenService(nnAddr);
      NuCypherExtClientProtocol proxy = createNonHAProxyWithNuCypherExtClientProtocol(nnAddr, conf,
          UserGroupInformation.getCurrentUser(), true, fallbackToSimpleAuth);
      return new ProxyAndInfo<>(proxy, dtService, nnAddr);
    } else {
      return createHAProxy(conf, nameNodeUri, NuCypherExtClientProtocol.class,
          failoverProxyProvider);
    }
  }

  /**
   * Generate a dummy namenode proxy instance that utilizes our hacked
   * {@link LossyRetryInvocationHandler}. Proxy instance generated using this
   * method will proactively drop RPC responses. Currently this method only
   * support HA setup. null will be returned if the given configuration is not
   * for HA.
   *
   * @param config the configuration containing the required IPC
   *        properties, client failover configurations, etc.
   * @param nameNodeUri the URI pointing either to a specific NameNode
   *        or to a logical nameservice.
   * @param xface the IPC interface which should be created
   * @param numResponseToDrop The number of responses to drop for each RPC call
   * @param fallbackToSimpleAuth set to true or false during calls to indicate
   *        if a secure client falls back to simple auth
   * @return an object containing both the proxy and the associated
   *         delegation token service it corresponds to. Will return null of the
   *         given configuration does not support HA.
   * @throws IOException if there is an error creating the proxy
   */
  public static <T> ProxyAndInfo<T> createProxyWithLossyRetryHandler(
      Configuration config, URI nameNodeUri, Class<T> xface,
      int numResponseToDrop, AtomicBoolean fallbackToSimpleAuth)
      throws IOException {
    Preconditions.checkArgument(numResponseToDrop > 0);
    AbstractNNFailoverProxyProvider<T> failoverProxyProvider =
        createFailoverProxyProvider(config, nameNodeUri, xface, true,
            fallbackToSimpleAuth);

    if (failoverProxyProvider != null) { // HA case
      int delay = config.getInt(
          HdfsClientConfigKeys.Failover.SLEEPTIME_BASE_KEY,
          HdfsClientConfigKeys.Failover.SLEEPTIME_BASE_DEFAULT);
      int maxCap = config.getInt(
          HdfsClientConfigKeys.Failover.SLEEPTIME_MAX_KEY,
          HdfsClientConfigKeys.Failover.SLEEPTIME_MAX_DEFAULT);
      int maxFailoverAttempts = config.getInt(
          HdfsClientConfigKeys.Failover.MAX_ATTEMPTS_KEY,
          HdfsClientConfigKeys.Failover.MAX_ATTEMPTS_DEFAULT);
      int maxRetryAttempts = config.getInt(
          HdfsClientConfigKeys.Retry.MAX_ATTEMPTS_KEY,
          HdfsClientConfigKeys.Retry.MAX_ATTEMPTS_DEFAULT);
      InvocationHandler dummyHandler = new LossyRetryInvocationHandler<>(
              numResponseToDrop, failoverProxyProvider,
              RetryPolicies.failoverOnNetworkException(
                  RetryPolicies.TRY_ONCE_THEN_FAIL, maxFailoverAttempts,
                  Math.max(numResponseToDrop + 1, maxRetryAttempts), delay,
                  maxCap));

      @SuppressWarnings("unchecked")
      T proxy = (T) Proxy.newProxyInstance(
          failoverProxyProvider.getInterface().getClassLoader(),
          new Class[]{xface}, dummyHandler);
      Text dtService;
      if (failoverProxyProvider.useLogicalURI()) {
        dtService = HAUtilClient.buildTokenServiceForLogicalUri(nameNodeUri,
            HdfsConstants.HDFS_URI_SCHEME);
      } else {
        dtService = SecurityUtil.buildTokenService(
            NuCypherExtUtilClient.getNNAddress(nameNodeUri));
      }
      return new ProxyAndInfo<>(proxy, dtService,
          NuCypherExtUtilClient.getNNAddress(nameNodeUri));
    } else {
      LOG.warn("Currently creating proxy using " +
          "LossyRetryInvocationHandler requires NN HA setup");
      return null;
    }
  }

  /** Creates the Failover proxy provider instance*/
  @VisibleForTesting
  public static <T> AbstractNNFailoverProxyProvider<T> createFailoverProxyProvider(
      Configuration conf, URI nameNodeUri, Class<T> xface, boolean checkPort,
      AtomicBoolean fallbackToSimpleAuth) throws IOException {
    Class<FailoverProxyProvider<T>> failoverProxyProviderClass = null;
    AbstractNNFailoverProxyProvider<T> providerNN;
    try {
      // Obtain the class of the proxy provider
      failoverProxyProviderClass = getFailoverProxyProviderClass(conf,
          nameNodeUri);
      if (failoverProxyProviderClass == null) {
        return null;
      }
      // Create a proxy provider instance.
      Constructor<FailoverProxyProvider<T>> ctor = failoverProxyProviderClass
          .getConstructor(Configuration.class, URI.class, Class.class);
      FailoverProxyProvider<T> provider = ctor.newInstance(conf, nameNodeUri,
          xface);

      // If the proxy provider is of an old implementation, wrap it.
      if (!(provider instanceof AbstractNNFailoverProxyProvider)) {
        providerNN = new WrappedFailoverProxyProvider<>(provider);
      } else {
        providerNN = (AbstractNNFailoverProxyProvider<T>)provider;
      }
    } catch (Exception e) {
      final String message = "Couldn't create proxy provider " +
          failoverProxyProviderClass;
      LOG.debug(message, e);
      if (e.getCause() instanceof IOException) {
        throw (IOException) e.getCause();
      } else {
        throw new IOException(message, e);
      }
    }

    // Check the port in the URI, if it is logical.
    if (checkPort && providerNN.useLogicalURI()) {
      int port = nameNodeUri.getPort();
      if (port > 0 &&
          port != HdfsClientConfigKeys.DFS_NAMENODE_RPC_PORT_DEFAULT) {
        // Throwing here without any cleanup is fine since we have not
        // actually created the underlying proxies yet.
        throw new IOException("Port " + port + " specified in URI "
            + nameNodeUri + " but host '" + nameNodeUri.getHost()
            + "' is a logical (HA) namenode"
            + " and does not use port information.");
      }
    }
    providerNN.setFallbackToSimpleAuth(fallbackToSimpleAuth);
    return providerNN;
  }

  /** Gets the configured Failover proxy provider's class */
  @VisibleForTesting
  public static <T> Class<FailoverProxyProvider<T>> getFailoverProxyProviderClass(
      Configuration conf, URI nameNodeUri) throws IOException {
    if (nameNodeUri == null) {
      return null;
    }
    String host = nameNodeUri.getHost();
    String configKey = HdfsClientConfigKeys.Failover.PROXY_PROVIDER_KEY_PREFIX
        + "." + host;
    try {
      @SuppressWarnings("unchecked")
      Class<FailoverProxyProvider<T>> ret = (Class<FailoverProxyProvider<T>>)
          conf.getClass(configKey, null, FailoverProxyProvider.class);
      return ret;
    } catch (RuntimeException e) {
      if (e.getCause() instanceof ClassNotFoundException) {
        throw new IOException("Could not load failover proxy provider class "
            + conf.get(configKey) + " which is configured for authority "
            + nameNodeUri, e);
      } else {
        throw e;
      }
    }
  }

  /**
   * Creates an explicitly HA-enabled proxy object.
   *
   * @param conf the configuration object
   * @param nameNodeUri the URI pointing either to a specific NameNode or to a
   *        logical nameservice.
   * @param xface the IPC interface which should be created
   * @param failoverProxyProvider Failover proxy provider
   * @return an object containing both the proxy and the associated
   *         delegation token service it corresponds to
   */
  @SuppressWarnings("unchecked")
  public static <T> ProxyAndInfo<T> createHAProxy(
      Configuration conf, URI nameNodeUri, Class<T> xface,
      AbstractNNFailoverProxyProvider<T> failoverProxyProvider) {
    Preconditions.checkNotNull(failoverProxyProvider);
    // HA case
    DfsClientConf config = new DfsClientConf(conf);
    T proxy = (T) RetryProxy.create(xface, failoverProxyProvider,
        RetryPolicies.failoverOnNetworkException(
            RetryPolicies.TRY_ONCE_THEN_FAIL, config.getMaxFailoverAttempts(),
            config.getMaxRetryAttempts(), config.getFailoverSleepBaseMillis(),
            config.getFailoverSleepMaxMillis()));

    Text dtService;
    if (failoverProxyProvider.useLogicalURI()) {
      dtService = HAUtilClient.buildTokenServiceForLogicalUri(nameNodeUri,
          HdfsConstants.HDFS_URI_SCHEME);
    } else {
      dtService = SecurityUtil.buildTokenService(
          NuCypherExtUtilClient.getNNAddress(nameNodeUri));
    }
    return new ProxyAndInfo<>(proxy, dtService,
        NuCypherExtUtilClient.getNNAddressCheckLogical(conf, nameNodeUri));
  }

  public static NuCypherExtClientProtocol createNonHAProxyWithNuCypherExtClientProtocol(
      InetSocketAddress address, Configuration conf, UserGroupInformation ugi,
      boolean withRetries, AtomicBoolean fallbackToSimpleAuth)
      throws IOException {
    RPC.setProtocolEngine(conf, NuCypherExtClientNamenodeProtocolPB.class,
        ProtobufRpcEngine.class);

    final RetryPolicy defaultPolicy = RetryPolicies.TRY_ONCE_THEN_FAIL;
/*
    TODO do smth with 2.6 compatibility, because signature was changed
    RetryUtils.getDefaultRetryPolicy(
            conf,
            HdfsClientConfigKeys.Retry.POLICY_ENABLED_KEY,
            HdfsClientConfigKeys.Retry.POLICY_ENABLED_DEFAULT,
            HdfsClientConfigKeys.Retry.POLICY_SPEC_KEY,
            HdfsClientConfigKeys.Retry.POLICY_SPEC_DEFAULT,
            SafeModeException.class)
           // SafeModeException.class.getName());
*/
    final long version = RPC.getProtocolVersion(NuCypherExtClientNamenodeProtocolPB.class);
    NuCypherExtClientNamenodeProtocolPB proxy = RPC.getProtocolProxy(
        NuCypherExtClientNamenodeProtocolPB.class, version, address, ugi, conf,
        NetUtils.getDefaultSocketFactory(conf),
        org.apache.hadoop.ipc.Client.getTimeout(conf), defaultPolicy,
        fallbackToSimpleAuth).getProxy();

    if (withRetries) { // create the proxy with retries
      Map<String, RetryPolicy> methodNameToPolicyMap = new HashMap<>();
      NuCypherExtClientProtocol translatorProxy =
          new NuCypherExtClientNamenodeProtocolTranslatorPB(proxy);
      return (NuCypherExtClientProtocol) RetryProxy.create(
          NuCypherExtClientProtocol.class,
          new DefaultFailoverProxyProvider<>(NuCypherExtClientProtocol.class,
              translatorProxy),
          methodNameToPolicyMap,
          defaultPolicy);
    } else {
      return new NuCypherExtClientNamenodeProtocolTranslatorPB(proxy);
    }
  }

}
