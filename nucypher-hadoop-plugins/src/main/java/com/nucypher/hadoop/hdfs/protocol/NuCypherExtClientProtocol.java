package com.nucypher.hadoop.hdfs.protocol;


import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.fs.XAttr;
import org.apache.hadoop.fs.XAttrSetFlag;
import org.apache.hadoop.hdfs.security.token.delegation.DelegationTokenSelector;
import org.apache.hadoop.io.retry.AtMostOnce;
import org.apache.hadoop.security.KerberosInfo;
import org.apache.hadoop.security.token.TokenInfo;

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.apache.hadoop.hdfs.client.HdfsClientConfigKeys.DFS_NAMENODE_KERBEROS_PRINCIPAL_KEY;

/**********************************************************************
 * NuCypherExtClientProtocol is used by user code via the DistributedFileSystem class to
 * communicate with the NameNode.
 *
 **********************************************************************/
@InterfaceAudience.Private
@InterfaceStability.Evolving
@KerberosInfo(
    serverPrincipal = DFS_NAMENODE_KERBEROS_PRINCIPAL_KEY)
@TokenInfo(DelegationTokenSelector.class)
public interface NuCypherExtClientProtocol {

  long versionID = 0L;


  /**
   * Set xattr of a file or directory.
   * The name must be prefixed with the namespace followed by ".". For example,
   * "user.attr".
   * Refer to the HDFS extended attributes user documentation for details.
   *
   * @param xAttrs map from <code>src</code> to <code>XAttr</code> to set
   * @param flag set flag
   * @throws IOException
   */
  @AtMostOnce
  void setXAttrs(Map<String, List<XAttr>> xAttrs, EnumSet<XAttrSetFlag> flag)
      throws IOException;
}
