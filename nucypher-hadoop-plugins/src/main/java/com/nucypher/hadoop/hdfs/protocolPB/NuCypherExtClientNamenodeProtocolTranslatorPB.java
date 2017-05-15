package com.nucypher.hadoop.hdfs.protocolPB;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.fs.XAttr;
import org.apache.hadoop.fs.XAttrSetFlag;
import org.apache.hadoop.ipc.*;

import com.nucypher.hadoop.hdfs.protocol.NuCypherExtClientProtocol;
import com.nucypher.hadoop.hdfs.protocol.proto.NuCypherExtClientNamenodeProtocolProtos.SetXAttrSingleRequestProto;
import com.nucypher.hadoop.hdfs.protocol.proto.NuCypherExtClientNamenodeProtocolProtos.SetXAttrsRequestProto;


import java.io.Closeable;
import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import com.google.protobuf.ServiceException;


/**
 * This class forwards NN's NuCypherExtClientProtocol calls as RPC calls to the NN server
 * while translating from the parameter types used in ClientProtocol to the
 * new PB types.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public class NuCypherExtClientNamenodeProtocolTranslatorPB implements
    ProtocolMetaInterface, NuCypherExtClientProtocol, Closeable, ProtocolTranslator {
  final private NuCypherExtClientNamenodeProtocolPB rpcProxy;

  public NuCypherExtClientNamenodeProtocolTranslatorPB(NuCypherExtClientNamenodeProtocolPB proxy) {
    rpcProxy = proxy;
  }

  @Override
  public void close() {
    RPC.stopProxy(rpcProxy);
  }

  @Override
  public void setXAttrs(Map<String, List<XAttr>> xAttrsToSet, EnumSet<XAttrSetFlag> flag)
      throws IOException {

    SetXAttrsRequestProto.Builder builder = SetXAttrsRequestProto.newBuilder();
    for (String src : xAttrsToSet.keySet()) {
      List<XAttr> xAttrs = xAttrsToSet.get(src);
      SetXAttrSingleRequestProto singleReq = SetXAttrSingleRequestProto.newBuilder()
          .setSrc(src)
          .addAllXAttr(NuCypherExtPBHelperClient.convertXAttrProto(xAttrs))
          .build();
      builder.addXAttrsToSet(singleReq);
    }
    SetXAttrsRequestProto req = builder.setFlag(NuCypherExtPBHelperClient.convert(flag)).build();
    try {
      rpcProxy.setXAttrs(null, req);
    } catch (ServiceException e) {
      throw ProtobufHelper.getRemoteException(e);
    }
  }

  @Override
  public boolean isMethodSupported(String methodName) throws IOException {
    return RpcClientUtil.isMethodSupported(rpcProxy,
        NuCypherExtClientNamenodeProtocolPB.class, RPC.RpcKind.RPC_PROTOCOL_BUFFER,
        RPC.getProtocolVersion(NuCypherExtClientNamenodeProtocolPB.class), methodName);
  }

  @Override
  public Object getUnderlyingProxyObject() {
    return rpcProxy;
  }
}
