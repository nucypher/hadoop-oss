package com.nucypher.hadoop.hdfs.plugin;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.server.namenode.NameNode;
import org.apache.hadoop.hdfs.server.namenode.NuCypherExtRpcServer;
import org.apache.hadoop.util.ServicePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class NuCypherExtServicePlugin implements ServicePlugin{

  public static final Logger LOG = LoggerFactory.getLogger(NuCypherExtServicePlugin.class);

  private NuCypherExtRpcServer rpcServer;

  @Override
  public void start(Object service) {
    NameNode nn = (NameNode)service;
    Configuration conf = null;
    try {
      conf = nn.getConf();
    } catch (NoSuchMethodError ex)
    {
      LOG.warn("No method getConf() in this NameNode : " + ex);
    }
    try {
      rpcServer = new NuCypherExtRpcServer(conf, nn);
      rpcServer.start();
      LOG.info(toString() +
          " started");
    } catch (IOException e) {
      LOG.error("Cannot create NuCypherExtRpcServer: " + e);
    }
  }

  @Override
  public void stop() {
    if (rpcServer != null)
      rpcServer.stop();
  }

  @Override
  public String toString()
  {
    return "NuCypher Hadoop Extension Plugin v" + getClass().getPackage().getImplementationVersion();
  }

  @Override
  public void close() throws IOException {

  }
}
