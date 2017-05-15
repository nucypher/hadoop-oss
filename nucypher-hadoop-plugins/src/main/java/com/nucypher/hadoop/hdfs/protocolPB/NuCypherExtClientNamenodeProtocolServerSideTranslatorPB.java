package com.nucypher.hadoop.hdfs.protocolPB;

import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;
import com.nucypher.hadoop.hdfs.protocol.NuCypherExtClientProtocol;
import com.nucypher.hadoop.hdfs.protocol.proto.NuCypherExtClientNamenodeProtocolProtos.SetXAttrsResponseProto;
import com.nucypher.hadoop.hdfs.protocol.proto.NuCypherExtClientNamenodeProtocolProtos.SetXAttrsRequestProto;
import com.nucypher.hadoop.hdfs.protocol.proto.NuCypherExtClientNamenodeProtocolProtos.SetXAttrSingleRequestProto;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.fs.XAttr;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is used on the server side. Calls come across the wire for the
 * for protocol {@link NuCypherExtClientNamenodeProtocolPB}.
 * This class translates the PB data types
 * to the native data types used inside the NN as specified in the generic
 * ClientProtocol.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public class NuCypherExtClientNamenodeProtocolServerSideTranslatorPB implements
    NuCypherExtClientNamenodeProtocolPB {

  final private NuCypherExtClientProtocol server;

  private static final SetXAttrsResponseProto
      VOID_SETXATTRS_RESPONSE = SetXAttrsResponseProto.getDefaultInstance();

  /**
   * Constructor
   *
   * @param server - the NN server
   * @throws IOException
   */
  public NuCypherExtClientNamenodeProtocolServerSideTranslatorPB(NuCypherExtClientProtocol server)
      throws IOException {
    this.server = server;
  }


  @Override
  public SetXAttrsResponseProto setXAttrs(RpcController controller,
                                        SetXAttrsRequestProto req) throws ServiceException {
    try {
      Map<String, List<XAttr>> xAttrs = new HashMap<>();
      for (SetXAttrSingleRequestProto singleReq : req.getXAttrsToSetList())
      {
          xAttrs.put(singleReq.getSrc(), NuCypherExtPBHelperClient.convertXAttrs(singleReq.getXAttrList()));
      }
      server.setXAttrs(xAttrs, NuCypherExtPBHelperClient.convert(req.getFlag()));
    } catch (IOException e) {
      throw new ServiceException(e);
    }
    return VOID_SETXATTRS_RESPONSE;
  }

}

