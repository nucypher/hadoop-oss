package com.nucypher.hadoop.hdfs.protocolPB;

import com.nucypher.hadoop.hdfs.NuCypherExtConstants;
import com.nucypher.hadoop.hdfs.protocol.proto.NuCypherExtClientNamenodeProtocolProtos.NuCypherExtClientNamenodeProtocol;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.hdfs.client.HdfsClientConfigKeys;
import org.apache.hadoop.hdfs.security.token.delegation.DelegationTokenSelector;
import org.apache.hadoop.ipc.ProtocolInfo;
import org.apache.hadoop.security.KerberosInfo;
import org.apache.hadoop.security.token.TokenInfo;

@InterfaceAudience.Private
@InterfaceStability.Stable
@KerberosInfo(
    serverPrincipal = HdfsClientConfigKeys.DFS_NAMENODE_KERBEROS_PRINCIPAL_KEY)
@TokenInfo(DelegationTokenSelector.class)
@ProtocolInfo(protocolName = NuCypherExtConstants.ZERO_DB_EXT_CLIENT_NAMENODE_PROTOCOL_NAME,
    protocolVersion = 1)

public interface NuCypherExtClientNamenodeProtocolPB  extends NuCypherExtClientNamenodeProtocol.BlockingInterface {
}
