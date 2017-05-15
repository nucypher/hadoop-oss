package org.apache.hadoop.hdfs.server.namenode;

import com.google.protobuf.BlockingService;
import com.nucypher.hadoop.hdfs.protocol.NuCypherExtClientProtocol;
import org.apache.hadoop.HadoopIllegalArgumentException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.hdfs.HDFSPolicyProvider;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.protocol.*;
import org.apache.hadoop.ipc.*;

import com.nucypher.hadoop.hdfs.protocol.proto.NuCypherExtClientNamenodeProtocolProtos.NuCypherExtClientNamenodeProtocol;
import com.nucypher.hadoop.hdfs.protocolPB.NuCypherExtClientNamenodeProtocolPB;
import com.nucypher.hadoop.hdfs.protocolPB.NuCypherExtClientNamenodeProtocolServerSideTranslatorPB;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.AccessControlException;
import org.apache.hadoop.security.token.SecretManager;
import org.slf4j.Logger;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.apache.hadoop.hdfs.DFSConfigKeys.DFS_NAMENODE_HANDLER_COUNT_DEFAULT;
import static org.apache.hadoop.hdfs.DFSConfigKeys.DFS_NAMENODE_HANDLER_COUNT_KEY;


/**
 * This class is responsible for handling all of the RPC calls to the NameNode.
 * It is created, started, and stopped by {@link NameNode}.
 */
public class NuCypherExtRpcServer implements NuCypherExtClientProtocol {

  public static final String  NUCYPHER_EXT_NAMENODE_SERVICE_RPC_ADDRESS_KEY = "nucypher.ext.servicerpc-address";

  private static final Logger LOG = NameNode.LOG;

  public static final int DEFAULT_PORT = 8122;

  // Dependencies from other parts of NN.
  protected final FSNamesystem namesystem;
  protected final NameNode nn;
  protected final RPC.Server rpcServer;
  protected final InetSocketAddress rpcAddress;
  protected Method setXAttrMethod = null;


  private final boolean serviceAuthEnabled;

  private final RetryCache retryCache;


  public NuCypherExtRpcServer(Configuration conf, NameNode nn)
      throws IOException {
    this.nn = nn;
    this.namesystem = nn.getNamesystem();
    this.retryCache = namesystem.getRetryCache();

    if (conf == null)
      conf = new HdfsConfiguration();

    int handlerCount =
        conf.getInt(DFS_NAMENODE_HANDLER_COUNT_KEY,
            DFS_NAMENODE_HANDLER_COUNT_DEFAULT);

    RPC.setProtocolEngine(conf, NuCypherExtClientNamenodeProtocolPB.class,
        ProtobufRpcEngine.class);

    NuCypherExtClientNamenodeProtocolServerSideTranslatorPB
        clientProtocolServerTranslator =
        new NuCypherExtClientNamenodeProtocolServerSideTranslatorPB(this);
    BlockingService clientNNPbService = NuCypherExtClientNamenodeProtocol.
        newReflectiveBlockingService(clientProtocolServerTranslator);

    InetSocketAddress rpcAddr = getServiceAddress(conf, nn.getRpcServerAddress(conf));
    String bindHost = nn.getServiceRpcServerBindHost(conf);
    if (bindHost == null) {
      bindHost = rpcAddr.getHostName();
    }

    LOG.info("NuCypher Extension RPC server is binding to " + bindHost + ":" + rpcAddr.getPort());

    rpcServer = new RPC.Builder(conf)
        .setProtocol(
            com.nucypher.hadoop.hdfs.protocolPB.NuCypherExtClientNamenodeProtocolPB.class)
        .setInstance(clientNNPbService)
        .setBindAddress(bindHost)
        .setPort(rpcAddr.getPort())
        .setNumHandlers(handlerCount)
        .setVerbose(false)
        .setSecretManager(namesystem.getDelegationTokenSecretManager())
        .build();


    // set service-level authorization security policy
    if (serviceAuthEnabled =
        conf.getBoolean(
            CommonConfigurationKeys.HADOOP_SECURITY_AUTHORIZATION, false)) {
      rpcServer.refreshServiceAcl(conf, new HDFSPolicyProvider());
    }

    // The rpc-server port can be ephemeral... ensure we have the correct info
    InetSocketAddress listenAddr = rpcServer.getListenerAddress();
    rpcAddress = new InetSocketAddress(
        rpcAddr.getHostName(), listenAddr.getPort());

    rpcServer.addTerseExceptions(SafeModeException.class,
        FileNotFoundException.class,
        HadoopIllegalArgumentException.class,
        FileAlreadyExistsException.class,
        InvalidPathException.class,
        ParentNotDirectoryException.class,
        UnresolvedLinkException.class,
        AlreadyBeingCreatedException.class,
        QuotaExceededException.class,
        RecoveryInProgressException.class,
        AccessControlException.class,
        SecretManager.InvalidToken.class,
        LeaseExpiredException.class,
        NSQuotaExceededException.class,
        DSQuotaExceededException.class,
//        QuotaByStorageTypeExceededException.class,
        AclException.class,
        FSLimitException.PathComponentTooLongException.class,
        FSLimitException.MaxDirectoryItemsExceededException.class,
        UnresolvedPathException.class);

    try {
      rpcServer.addSuppressedLoggingExceptions(StandbyException.class);
    } catch (NoSuchMethodError ex)
    {
      LOG.warn("no method addSuppressedLoggingExceptions in RPC.Server : " + ex);
    }
    rpcServer.setTracer(nn.tracer);

    try {
      setXAttrMethod = FSNamesystem.class.getDeclaredMethod("setXAttr", String.class, XAttr.class, EnumSet.class, boolean.class);
    } catch (NoSuchMethodException | SecurityException ex)
    {
      LOG.warn("NuCypherExt: Cannot find method FSNamesystem.setXAttr(String src, XAttr xAttr, EnumSet<XAttrSetFlag> flag," +
          " boolean logRetryCache), trying verison from 2.6 : " + ex);
    }

    if (setXAttrMethod == null) {
      try {
        //setXAttrMethod = FSNamesystem.class.getDeclaredMethod("setXAttr", String.class, XAttr.class, EnumSet.class);
        setXAttrMethod = FSNamesystem.class.getDeclaredMethod("setXAttrInt", String.class, XAttr.class, EnumSet.class, boolean.class);
        setXAttrMethod.setAccessible(true);
      } catch (NoSuchMethodException ex) {
        LOG.error("NuCypherExt: Cannot find method FSNamesystem.setXAttrInt(String src, XAttr xAttr, EnumSet<XAttrSetFlag> flag , boolean logRetryCache), cannot handle request:", ex);
        throw new IOException(ex.toString());
      }
    } else
      setXAttrMethod = null;

  }

  private void setXAttrInt(String src, XAttr xAttr, EnumSet<XAttrSetFlag> flag,
                      boolean logRetryCache) throws IOException
  {
    try {
      if (setXAttrMethod != null)
        setXAttrMethod.invoke(namesystem, src, xAttr, flag, logRetryCache);
      else
        namesystem.setXAttr(src, xAttr, flag, logRetryCache);
    } catch (IllegalAccessException | InvocationTargetException ex) {
      LOG.error("Cannot call setXAttrMethod: " + ex);
      throw new IOException(ex.toString());
    }
  }

  @Override // NuCypherExtClientProtocol
  public void setXAttrs(Map<String, List<XAttr>> xAttrToSet, EnumSet<XAttrSetFlag> flag)
      throws IOException {
    checkNNStartup();
    namesystem.checkOperation(NameNode.OperationCategory.WRITE);
    RetryCache.CacheEntry cacheEntry = RetryCache.waitForCompletion(retryCache);
    if (cacheEntry != null && cacheEntry.isSuccess()) {
      return; // Return previous response
    }
    boolean success = false;
    try {
      for (Map.Entry<String, List<XAttr>> entry : xAttrToSet.entrySet()) {
        for (XAttr xAttr : entry.getValue())
          setXAttrInt(entry.getKey(), xAttr, flag, cacheEntry != null);
      }
      success = true;
    } finally {
        RetryCache.setState(cacheEntry, success);
    }
  }

  private void checkNNStartup() throws IOException {
    if (!this.nn.isStarted()) {
      throw new RetriableException(this.nn.getRole() + " still not started");
    }
  }

  public static InetSocketAddress getServiceAddress(Configuration conf, InetSocketAddress fallback) {
    String addr = conf.get(NUCYPHER_EXT_NAMENODE_SERVICE_RPC_ADDRESS_KEY);
    if (addr == null || addr.isEmpty()) {
      return InetSocketAddress.createUnresolved(fallback.getHostName(), DEFAULT_PORT);
    }
    return NuCypherExtRpcServer.getAddress(addr);
  }

  public static InetSocketAddress getAddress(String address) {
    return NetUtils.createSocketAddr(address, DEFAULT_PORT);
  }


  public void start() {
    rpcServer.start();
  }

  public void stop() {
    if (rpcServer != null) {
      rpcServer.stop();
    }
  }
}
