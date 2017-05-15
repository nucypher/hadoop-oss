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

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EncryptedKeyVersion;
import org.apache.hadoop.crypto.key.kms.KMSClientProvider;
import org.apache.hadoop.crypto.key.kms.KMSRESTConstants;
import org.apache.hadoop.crypto.key.pre.RENRESTConstants;
import org.apache.hadoop.crypto.key.pre.ReEncryptionKeyProviderInterface;
import org.apache.hadoop.security.AccessControlException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.delegation.web.HttpUserGroupInformation;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.PrivilegedExceptionAction;
import java.util.*;

/**
 * Class providing the REST bindings, via Jersey, for the KMS.
 */
@Path(RENRESTConstants.SERVICE_VERSION)
@InterfaceAudience.Private
public class REN {

  public static enum RENOp {
    TRANSFORM_EEK,
    DELETE_REK
  }

  private ReEncryptionKeyProviderInterface provider;
  private RENAudit renAudit;

  public REN() throws Exception {
    provider = KMSWebApp.getReEncryptionKeyProvider();
    renAudit = KMSWebApp.getRENAudit();
  }
  private void assertAccess(KMSACLs.Type aclType, UserGroupInformation ugi,
      RENOp operation) throws AccessControlException {
    KMSWebApp.getACLs().assertAccess(aclType, ugi, operation, null);
  }

  private void assertAccess(KMSACLs.Type aclType, UserGroupInformation ugi,
      RENOp operation, String key) throws AccessControlException {
    KMSWebApp.getACLs().assertAccess(aclType, ugi, operation, key);
  }


  @DELETE
  @Path(RENRESTConstants.KEY_VERSION_SRC_DST_RESOURCE + "/{src.name:.*}/{dst.name:.*}")
  public Response deleteKey(@PathParam("src.name") final String srcName,
                            @PathParam("dst.name") final String dstName)
      throws Exception {
    KMSWebApp.getAdminCallsMeter().mark();
    UserGroupInformation user = HttpUserGroupInformation.get();
    assertAccess(KMSACLs.Type.DELETE_REK, user, RENOp.DELETE_REK, srcName + "->" + dstName);
    // can delete keys by dst or src name
    if ((srcName == null || srcName.isEmpty()) &&
        (dstName == null || dstName.isEmpty()))
      throw new IllegalArgumentException("Parameter '" + "src.name" + "and" + "dst.name" +
          "' cannot be empty");

    user.doAs(new PrivilegedExceptionAction<Void>() {
      @Override
      public Void run() throws Exception {
        provider.deleteReEncryptionKey(srcName, dstName);
        //provider.flush();
        return null;
      }
    });

   renAudit.ok(user, RENOp.DELETE_REK, srcName + "->" + dstName, "");

    return Response.ok().build();
  }

  @SuppressWarnings("rawtypes")
  @POST
  @Path(RENRESTConstants.KEY_VERSION_RESOURCE + "/{dstVersionName:.*}/" +
      RENRESTConstants.REK_SUB_RESOURCE)
  @Produces(MediaType.APPLICATION_JSON)
  public Response decryptEncryptedKey(
      @PathParam("dstVersionName") final String dstVersionName,
      @QueryParam(RENRESTConstants.REN_OP) String renOp,
      Map jsonPayload)
      throws Exception {
    UserGroupInformation user = HttpUserGroupInformation.get();
    KMSClientProvider.checkNotEmpty(dstVersionName, "dstVersionName");
    KMSClientProvider.checkNotNull(renOp, "renOp");

    final String keyName = (String) jsonPayload.get(
        KMSRESTConstants.NAME_FIELD);
    final String keyVersionName = (String) jsonPayload.get(
        KMSRESTConstants.VERSION_NAME_FIELD);
    String ivStr = (String) jsonPayload.get(KMSRESTConstants.IV_FIELD);
    String encMaterialStr =
        (String) jsonPayload.get(KMSRESTConstants.MATERIAL_FIELD);
    Object retJSON;
    if (renOp.equals(RENRESTConstants.REN_TRANSFORM)) {
      assertAccess(KMSACLs.Type.TRANSFORM_EEK, user, RENOp.TRANSFORM_EEK, keyName);
      KMSClientProvider.checkNotNull(ivStr, KMSRESTConstants.IV_FIELD);
      final byte[] iv = Base64.decodeBase64(ivStr);
      KMSClientProvider.checkNotNull(encMaterialStr,
          KMSRESTConstants.MATERIAL_FIELD);
      final byte[] encMaterial = Base64.decodeBase64(encMaterialStr);

      EncryptedKeyVersion retKeyVersion = user.doAs(
          new PrivilegedExceptionAction<EncryptedKeyVersion>() {
            @Override
            public EncryptedKeyVersion run() throws Exception {
              return provider.transformEncryptedKey(
                  new KMSClientProvider.KMSEncryptedKeyVersion(keyName,
                      keyVersionName, iv, KeyProviderCryptoExtension.EEK,
                      encMaterial),
                  dstVersionName
              );
            }
          }
      );

      final List<EncryptedKeyVersion> retEdeks =
        Collections.singletonList(retKeyVersion);

      renAudit.ok(user, RENOp.TRANSFORM_EEK,
          keyVersionName + "->" + dstVersionName, "");
      retJSON = new ArrayList();
      for (EncryptedKeyVersion edek : retEdeks) {
        ((ArrayList)retJSON).add(KMSServerJSONUtils.toJSON(edek));
      }
    } else {
      throw new IllegalArgumentException("Wrong " + RENRESTConstants.REN_OP +
          " value, it must be " + RENRESTConstants.REN_TRANSFORM);
    }
    KMSWebApp.getTransformEEKCallsMeter().mark();
    return Response.ok().type(MediaType.APPLICATION_JSON).entity(retJSON)
        .build();
  }
}
