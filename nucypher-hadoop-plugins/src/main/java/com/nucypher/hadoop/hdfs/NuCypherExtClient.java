package com.nucypher.hadoop.hdfs;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.net.InetAddresses;
import com.nucypher.hadoop.hdfs.protocol.NuCypherExtClientProtocol;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.hdfs.*;
import com.nucypher.hadoop.hdfs.NuCypherExtNameNodeProxiesClient.ProxyAndInfo;
import org.apache.hadoop.hdfs.client.HdfsClientConfigKeys;
import org.apache.hadoop.hdfs.protocol.NSQuotaExceededException;
import org.apache.hadoop.hdfs.protocol.SnapshotAccessControlException;
import org.apache.hadoop.hdfs.protocol.UnresolvedPathException;
import org.apache.hadoop.hdfs.server.namenode.SafeModeException;
import org.apache.hadoop.io.retry.LossyRetryInvocationHandler;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.ipc.RemoteException;
import org.apache.hadoop.net.DNS;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.AccessControlException;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.SocketFactory;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.apache.hadoop.hdfs.client.HdfsClientConfigKeys.*;

@InterfaceAudience.Private
public class NuCypherExtClient implements java.io.Closeable {
  public static final Logger LOG = LoggerFactory.getLogger(NuCypherExtClient.class);
  // 1 hour
  public static final long SERVER_DEFAULTS_VALIDITY_PERIOD = 60 * 60 * 1000L;

  private final Configuration conf;
  // private final DfsClientConf dfsClientConf;
  final NuCypherExtClientProtocol namenode;

  final UserGroupInformation ugi;
  volatile boolean clientRunning = true;
  final String clientName;
  final SocketFactory socketFactory;
  private final FileSystem.Statistics stats;
  private final String authority;
  private final Random r = new Random();
  private SocketAddress[] localInterfaceAddrs;
/*
  public DfsClientConf getConf() {
    return dfsClientConf;
  }
*/
  Configuration getConfiguration() {
    return conf;
  }

  /**
   * A map from file names to {@link DFSOutputStream} objects
   * that are currently being written by this client.
   * Note that a file can only be written by a single client.
   */
  private final Map<Long, DFSOutputStream> filesBeingWritten = new HashMap<>();

  /**
   * Same as this(NameNode.getNNAddress(conf), conf);
   * @see #NuCypherExtClient(InetSocketAddress, Configuration)
   * @deprecated Deprecated at 0.21
   */
  @Deprecated
  public NuCypherExtClient(Configuration conf) throws IOException {
    this(NuCypherExtUtilClient.getNNAddress(conf), conf);
  }

  public NuCypherExtClient(InetSocketAddress address, Configuration conf)
      throws IOException {
    this(NuCypherExtUtilClient.getNNUri(address), conf);
  }

  /**
   * Same as this(nameNodeUri, conf, null);
   * @see #NuCypherExtClient(URI, Configuration, FileSystem.Statistics)
   */
  public NuCypherExtClient(URI nameNodeUri, Configuration conf) throws IOException {
    this(nameNodeUri, conf, null);
  }

  /**
   * Same as this(nameNodeUri, null, conf, stats);
   * @see #NuCypherExtClient(URI, NuCypherExtClientProtocol, Configuration, FileSystem.Statistics)
   */
  public NuCypherExtClient(URI nameNodeUri, Configuration conf,
                         FileSystem.Statistics stats) throws IOException {
    this(nameNodeUri, null, conf, stats);
  }

  /**
   * Create a new NuCypherExtClient connected to the given nameNodeUri or rpcNamenode.
   * If HA is enabled and a positive value is set for
   * {@link HdfsClientConfigKeys#DFS_CLIENT_TEST_DROP_NAMENODE_RESPONSE_NUM_KEY}
   * in the configuration, the DFSClient will use
   * {@link LossyRetryInvocationHandler} as its RetryInvocationHandler.
   * Otherwise one of nameNodeUri or rpcNamenode must be null.
   */
  @VisibleForTesting
  public NuCypherExtClient(URI nameNodeUri, NuCypherExtClientProtocol rpcNamenode,
                         Configuration conf, FileSystem.Statistics stats) throws IOException {
 //   this.dfsClientConf = new DfsClientConf(conf);
    this.conf = conf;
    this.stats = stats;
    this.socketFactory = NetUtils.getSocketFactory(conf, NuCypherExtClientProtocol.class);

    this.ugi = UserGroupInformation.getCurrentUser();

    this.authority = nameNodeUri == null? "null": nameNodeUri.getAuthority();
    this.clientName = "NuCypherExtClient_" + conf.get("mapreduce.task.attempt.id", "NONMAPREDUCE") + "_" +
        ThreadLocalRandom.current().nextInt()  + "_" +
        Thread.currentThread().getId();
    int numResponseToDrop = conf.getInt(
        DFS_CLIENT_TEST_DROP_NAMENODE_RESPONSE_NUM_KEY,
        DFS_CLIENT_TEST_DROP_NAMENODE_RESPONSE_NUM_DEFAULT);
    ProxyAndInfo<NuCypherExtClientProtocol> proxyInfo = null;
    AtomicBoolean nnFallbackToSimpleAuth = new AtomicBoolean(false);

    if (numResponseToDrop > 0) {
      // This case is used for testing.
      LOG.warn(DFS_CLIENT_TEST_DROP_NAMENODE_RESPONSE_NUM_KEY
          + " is set to " + numResponseToDrop
          + ", this hacked client will proactively drop responses");
      proxyInfo = NuCypherExtNameNodeProxiesClient.createProxyWithLossyRetryHandler(conf,
          nameNodeUri, NuCypherExtClientProtocol.class, numResponseToDrop,
          nnFallbackToSimpleAuth);
    }

    if (proxyInfo != null) {
      // this.dtService = proxyInfo.getDelegationTokenService();
      this.namenode = proxyInfo.getProxy();
    } else if (rpcNamenode != null) {
      // This case is used for testing.
      Preconditions.checkArgument(nameNodeUri == null);
      this.namenode = rpcNamenode;
      //dtService = null;
    } else {
      Preconditions.checkArgument(nameNodeUri != null,
          "null URI");
      proxyInfo = NuCypherExtNameNodeProxiesClient.createProxyWithNuCypherExtClientProtocol(conf,
          nameNodeUri, nnFallbackToSimpleAuth);
      // this.dtService = proxyInfo.getDelegationTokenService();
      this.namenode = proxyInfo.getProxy();
    }

    String localInterfaces[] =
        conf.getTrimmedStrings(DFS_CLIENT_LOCAL_INTERFACES);
    localInterfaceAddrs = getLocalInterfaceAddrs(localInterfaces);
    if (LOG.isDebugEnabled() && 0 != localInterfaces.length) {
      LOG.debug("Using local interfaces [" +
          Joiner.on(',').join(localInterfaces)+ "] with addresses [" +
          Joiner.on(',').join(localInterfaceAddrs) + "]");
    }
  }

  /**
   * Return the socket addresses to use with each configured
   * local interface. Local interfaces may be specified by IP
   * address, IP address range using CIDR notation, interface
   * name (e.g. eth0) or sub-interface name (e.g. eth0:0).
   * The socket addresses consist of the IPs for the interfaces
   * and the ephemeral port (port 0). If an IP, IP range, or
   * interface name matches an interface with sub-interfaces
   * only the IP of the interface is used. Sub-interfaces can
   * be used by specifying them explicitly (by IP or name).
   *
   * @return SocketAddresses for the configured local interfaces,
   *    or an empty array if none are configured
   * @throws UnknownHostException if a given interface name is invalid
   */
  private static SocketAddress[] getLocalInterfaceAddrs(
      String interfaceNames[]) throws UnknownHostException {
    List<SocketAddress> localAddrs = new ArrayList<>();
    for (String interfaceName : interfaceNames) {
      if (InetAddresses.isInetAddress(interfaceName)) {
        localAddrs.add(new InetSocketAddress(interfaceName, 0));
      } else if (NetUtils.isValidSubnet(interfaceName)) {
        for (InetAddress addr : NetUtils.getIPs(interfaceName, false)) {
          localAddrs.add(new InetSocketAddress(addr, 0));
        }
      } else {
        for (String ip : DNS.getIPs(interfaceName, false)) {
          localAddrs.add(new InetSocketAddress(ip, 0));
        }
      }
    }
    return localAddrs.toArray(new SocketAddress[localAddrs.size()]);
  }

  /**
   * Select one of the configured local interfaces at random. We use a random
   * interface because other policies like round-robin are less effective
   * given that we cache connections to datanodes.
   *
   * @return one of the local interface addresses at random, or null if no
   *    local interfaces are configured
   */
  SocketAddress getRandomLocalInterfaceAddr() {
    if (localInterfaceAddrs.length == 0) {
      return null;
    }
    final int idx = r.nextInt(localInterfaceAddrs.length);
    final SocketAddress addr = localInterfaceAddrs[idx];
    LOG.debug("Using local interface {}", addr);
    return addr;
  }

  @VisibleForTesting
  public String getClientName() {
    return clientName;
  }

  void checkOpen() throws IOException {
    if (!clientRunning) {
      throw new IOException("Filesystem closed");
    }
  }

  /**
   * Close connections the Namenode.
   */
  void closeConnectionToNamenode() {
    RPC.stopProxy(namenode);
  }

  /**
   * Close the file system, abandoning all of the leases and files being
   * created and close connections to the namenode.
   */
  @Override
  public synchronized void close() throws IOException {
    if(clientRunning) {
      clientRunning = false;
      // close connections to the namenode
      closeConnectionToNamenode();
    }
  }

  public void setXAttrs(Map<String, Map<String, byte[]>> xAttrsToSetRaw,
      EnumSet<XAttrSetFlag> flag) throws IOException {
    checkOpen();

    try  {
      Map<String, List<XAttr>> xAttrsToSet = new HashMap<>();
      for (String src : xAttrsToSetRaw.keySet())
      {
        List<XAttr> list = new ArrayList<>();
        Map<String, byte[]> rawList = xAttrsToSetRaw.get(src);
        for (String attrName : rawList.keySet())
          list.add(XAttrHelper.buildXAttr(attrName, rawList.get(attrName)));
        xAttrsToSet.put(src, list);
      }
      namenode.setXAttrs(xAttrsToSet, flag);
    } catch (RemoteException re) {
      throw re.unwrapRemoteException(AccessControlException.class,
          FileNotFoundException.class,
          NSQuotaExceededException.class,
          SafeModeException.class,
          SnapshotAccessControlException.class,
          UnresolvedPathException.class);
    }
  }
}
