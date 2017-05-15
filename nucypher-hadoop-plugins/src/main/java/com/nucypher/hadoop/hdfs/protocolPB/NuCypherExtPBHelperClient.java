package com.nucypher.hadoop.hdfs.protocolPB;

import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import org.apache.hadoop.fs.XAttr;
import org.apache.hadoop.fs.XAttrSetFlag;
import org.apache.hadoop.hdfs.protocol.proto.XAttrProtos;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public class NuCypherExtPBHelperClient {

  private static final XAttr.NameSpace[] XATTR_NAMESPACE_VALUES =
      XAttr.NameSpace.values();

  private static <T extends Enum<T>, U extends Enum<U>> U castEnum(T from, U[] to) {
    return to[from.ordinal()];
  }
  public static ByteString getByteString(byte[] bytes) {
    // return singleton to reduce object allocation
    return (bytes.length == 0) ? ByteString.EMPTY : ByteString.copyFrom(bytes);
  }

  static XAttr.NameSpace convert(XAttrProtos.XAttrProto.XAttrNamespaceProto v) {
    return castEnum(v, XATTR_NAMESPACE_VALUES);
  }

  static XAttrProtos.XAttrProto.XAttrNamespaceProto convert(XAttr.NameSpace v) {
    return XAttrProtos.XAttrProto.XAttrNamespaceProto.valueOf(v.ordinal());
  }


  public static List<XAttrProtos.XAttrProto> convertXAttrProto(
      List<XAttr> xAttrSpec) {
    if (xAttrSpec == null) {
      return Lists.newArrayListWithCapacity(0);
    }
    ArrayList<XAttrProtos.XAttrProto> xAttrs = Lists.newArrayListWithCapacity(
        xAttrSpec.size());
    for (XAttr a : xAttrSpec) {
      XAttrProtos.XAttrProto.Builder builder = XAttrProtos.XAttrProto.newBuilder();
      builder.setNamespace(convert(a.getNameSpace()));
      if (a.getName() != null) {
        builder.setName(a.getName());
      }
      if (a.getValue() != null) {
        builder.setValue(getByteString(a.getValue()));
      }
      xAttrs.add(builder.build());
    }
    return xAttrs;
  }

  static List<XAttr> convertXAttrs(List<XAttrProtos.XAttrProto> xAttrSpec) {
    ArrayList<XAttr> xAttrs = Lists.newArrayListWithCapacity(xAttrSpec.size());
    for (XAttrProtos.XAttrProto a : xAttrSpec) {
      XAttr.Builder builder = new XAttr.Builder();
      builder.setNameSpace(convert(a.getNamespace()));
      if (a.hasName()) {
        builder.setName(a.getName());
      }
      if (a.hasValue()) {
        builder.setValue(a.getValue().toByteArray());
      }
      xAttrs.add(builder.build());
    }
    return xAttrs;
  }

  public static EnumSet<XAttrSetFlag> convert(int flag) {
    EnumSet<XAttrSetFlag> result =
        EnumSet.noneOf(XAttrSetFlag.class);
    if ((flag & XAttrProtos.XAttrSetFlagProto.XATTR_CREATE_VALUE) ==
        XAttrProtos.XAttrSetFlagProto.XATTR_CREATE_VALUE) {
      result.add(XAttrSetFlag.CREATE);
    }
    if ((flag & XAttrProtos.XAttrSetFlagProto.XATTR_REPLACE_VALUE) ==
        XAttrProtos.XAttrSetFlagProto.XATTR_REPLACE_VALUE) {
      result.add(XAttrSetFlag.REPLACE);
    }
    return result;
  }

  /**
   * The flag field in PB is a bitmask whose values are the same a the
   * emum values of XAttrSetFlag
   */
  public static int convert(EnumSet<XAttrSetFlag> flag) {
    int value = 0;
    if (flag.contains(XAttrSetFlag.CREATE)) {
      value |= XAttrProtos.XAttrSetFlagProto.XATTR_CREATE.getNumber();
    }
    if (flag.contains(XAttrSetFlag.REPLACE)) {
      value |= XAttrProtos.XAttrSetFlagProto.XATTR_REPLACE.getNumber();
    }
    return value;
  }
}
