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

package org.apache.hadoop.crypto.key.pre;
import com.google.common.base.Preconditions;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EncryptedKeyVersion;
import org.apache.hadoop.crypto.key.kms.KMSRESTConstants;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.security.ProviderUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.client.ConnectionConfigurator;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenAuthenticatedURL;
import org.apache.hadoop.util.HttpExceptionUtils;
import org.apache.http.client.utils.URIBuilder;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.PrivilegedExceptionAction;
import java.util.*;

/**
 * TODO extract all web-serivce sprcific client code to one parent class
 */
public class ReEncryptionClientProvider implements ReEncryptionKeyProviderInterface, Configurable {

  private static Logger LOG =
      LoggerFactory.getLogger(ReEncryptionClientProvider.class);

  public static final String SCHEME_NAME = "ren";

  private static final String UTF8 = "UTF-8";

  private static final String CONTENT_TYPE = "Content-Type";
  private static final String APPLICATION_JSON_MIME = "application/json";
  private static final String ANONYMOUS_REQUESTS_DISALLOWED = "Anonymous requests are disallowed";

  private static final String INVALID_SIGNATURE = "Invalid signature";

  private static final String CONFIG_PREFIX = "hadoop.security.ren.client.";

  private static final String HTTP_GET = "GET";
  private static final String HTTP_POST = "POST";
  private static final String HTTP_PUT = "PUT";
  private static final String HTTP_DELETE = "DELETE";

  /* It's possible to specify a timeout, in seconds, in the config file */
  public static final String TIMEOUT_ATTR = CONFIG_PREFIX + "timeout";
  public static final int DEFAULT_TIMEOUT = 60;

  /* Number of times to retry authentication in the event of auth failure
   * (normally happens due to stale authToken)
   */
  public static final String AUTH_RETRY = CONFIG_PREFIX
      + "authentication.retry-count";
  public static final int DEFAULT_AUTH_RETRY = 1;


  private Configuration conf;

  public ReEncryptionClientProvider(URI uri, Configuration conf) throws IOException {
    setConf(conf);
    renUrl = createServiceURL(ProviderUtils.unnestUri(uri));
    if ("https".equalsIgnoreCase(new URL(renUrl).getProtocol())) {
      sslFactory = new SSLFactory(SSLFactory.Mode.CLIENT, conf);
      try {
        sslFactory.init();
      } catch (GeneralSecurityException ex) {
        throw new IOException(ex);
      }
    }
    int timeout = conf.getInt(TIMEOUT_ATTR, DEFAULT_TIMEOUT);
    authRetry = conf.getInt(AUTH_RETRY, DEFAULT_AUTH_RETRY);
    configurator = new TimeoutConnConfigurator(timeout, sslFactory);

    authToken = new DelegationTokenAuthenticatedURL.Token();
    UserGroupInformation.AuthenticationMethod authMethod =
        UserGroupInformation.getCurrentUser().getAuthenticationMethod();
    if (authMethod == UserGroupInformation.AuthenticationMethod.PROXY) {
      actualUgi = UserGroupInformation.getCurrentUser().getRealUser();
    } else if (authMethod == UserGroupInformation.AuthenticationMethod.TOKEN) {
      actualUgi = UserGroupInformation.getLoginUser();
    } else {
      actualUgi =UserGroupInformation.getCurrentUser();
    }
  }

  @Override
  public EncryptedKeyVersion transformEncryptedKey(EncryptedKeyVersion encryptedKeyVersion, String destinationEncryptionKey)
      throws IOException, GeneralSecurityException
  {
      checkNotNull(encryptedKeyVersion.getEncryptionKeyVersionName(),
          "versionName");
      checkNotNull(encryptedKeyVersion.getEncryptedKeyIv(), "iv");
      Preconditions.checkArgument(
          encryptedKeyVersion.getEncryptedKeyVersion().getVersionName()
              .equals(KeyProviderCryptoExtension.EEK),
          "encryptedKey version name must be '%s', is '%s'",
          KeyProviderCryptoExtension.EEK,
          encryptedKeyVersion.getEncryptedKeyVersion().getVersionName()
      );
      checkNotNull(encryptedKeyVersion.getEncryptedKeyVersion(), "encryptedKey");
      checkNotNull(destinationEncryptionKey, "destinationEncryptionKey");
      Map<String, String> params = new HashMap<>();
      params.put(RENRESTConstants.REN_OP, RENRESTConstants.REN_TRANSFORM);
      Map<String, Object> jsonPayload = new HashMap<>();
      jsonPayload.put(KMSRESTConstants.NAME_FIELD,
          encryptedKeyVersion.getEncryptionKeyName());
      jsonPayload.put(KMSRESTConstants.VERSION_NAME_FIELD,
        encryptedKeyVersion.getEncryptionKeyVersionName());
      jsonPayload.put(KMSRESTConstants.IV_FIELD, Base64.encodeBase64String(
          encryptedKeyVersion.getEncryptedKeyIv()));
      jsonPayload.put(KMSRESTConstants.MATERIAL_FIELD, Base64.encodeBase64String(
          encryptedKeyVersion.getEncryptedKeyVersion().getMaterial()));
      URL url = createURL(RENRESTConstants.KEY_VERSION_RESOURCE,
            destinationEncryptionKey,
          RENRESTConstants.REK_SUB_RESOURCE, params);
      HttpURLConnection conn = createConnection(url, HTTP_POST);
      conn.setRequestProperty(CONTENT_TYPE, APPLICATION_JSON_MIME);
      List response =
          call(conn, jsonPayload, HttpURLConnection.HTTP_OK, List.class);

      List<EncryptedKeyVersion> ekvs =
        parseJSONEncKeyVersion(encryptedKeyVersion.getEncryptionKeyVersionName(), response);

      return ekvs.get(0);
    }

    @Override
    public void deleteReEncryptionKey(String srcName, String dstName) {
        // TODO;
    }

    @Override
    public void setConf(Configuration conf) {
        this.conf = conf;
    }

    @Override
    public Configuration getConf() {
        return conf;
    }

    public static class Factory extends ReEncryptionKeyProviderFactory {
        @Override
        public ReEncryptionKeyProviderInterface createProvider(URI providerName,
                                          Configuration conf) throws IOException {
            if (SCHEME_NAME.equals(providerName.getScheme())) {
                return new ReEncryptionClientProvider(providerName, conf);
            }
            return null;
        }
    }
    public static <T> T checkNotNull(T o, String name)
        throws IllegalArgumentException {
        if (o == null) {
            throw new IllegalArgumentException("Parameter '" + name +
                "' cannot be null");
        }
        return o;
    }

    public static String checkNotEmpty(String s, String name)
        throws IllegalArgumentException {
        checkNotNull(s, name);
        if (s.isEmpty()) {
            throw new IllegalArgumentException("Parameter '" + name +
                "' cannot be empty");
        }
        return s;
    }

    private String renUrl;
    private SSLFactory sslFactory;
    private ConnectionConfigurator configurator;
    private DelegationTokenAuthenticatedURL.Token authToken;
    private final int authRetry;
    private final UserGroupInformation actualUgi;

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("ReEncryptionClientProvider[");
        sb.append(renUrl).append("]");
        return sb.toString();
    }


  private URL createURL(String collection, String resource, String subResource,
                        Map<String, ?> parameters) throws IOException
  {
    return createURLFromList(collection, Collections.singletonList(resource), subResource, parameters);
  }

  private URL createURLFromList(String collection, List<String> resources, String subResource,
                                Map<String, ?> parameters) throws IOException
  {
    try {
      StringBuilder sb = new StringBuilder();
      sb.append(renUrl);
      if (collection != null) {
        sb.append(collection);
        if (resources != null) {
          boolean foundNotNull = false;
          for (String resource : resources) {
            if (resource != null) {
              sb.append("/").append(URLEncoder.encode(resource, UTF8));
              foundNotNull = true;
            }
          }
          if (foundNotNull && subResource != null) {
            sb.append("/").append(subResource);
          }
        }
      }
      URIBuilder uriBuilder = new URIBuilder(sb.toString());
      if (parameters != null) {
        for (Map.Entry<String, ?> param : parameters.entrySet()) {
          Object value = param.getValue();
          if (value instanceof String) {
            uriBuilder.addParameter(param.getKey(), (String) value);
          } else {
            for (String s : (String[]) value) {
              uriBuilder.addParameter(param.getKey(), s);
            }
          }
        }
      }
      return uriBuilder.build().toURL();
    } catch (URISyntaxException ex) {
      throw new IOException(ex);
    }
  }

  private HttpURLConnection createConnection(final URL url, String method)
      throws IOException {
    HttpURLConnection conn;
    try {
      // if current UGI is different from UGI at constructor time, behave as
      // proxyuser
      UserGroupInformation currentUgi = UserGroupInformation.getCurrentUser();
      final String doAsUser = (currentUgi.getAuthenticationMethod() ==
          UserGroupInformation.AuthenticationMethod.PROXY)
          ? currentUgi.getShortUserName() : null;

      // check and renew TGT to handle potential expiration
      actualUgi.checkTGTAndReloginFromKeytab();
      // creating the HTTP connection using the current UGI at constructor time
      conn = actualUgi.doAs(new PrivilegedExceptionAction<HttpURLConnection>() {
        @Override
        public HttpURLConnection run() throws Exception {
          DelegationTokenAuthenticatedURL authUrl =
              new DelegationTokenAuthenticatedURL(configurator);
          return authUrl.openConnection(url, authToken, doAsUser);
        }
      });
    } catch (IOException ex) {
      if (ex instanceof SocketTimeoutException) {
        LOG.warn("Failed to connect to {}:{}", url.getHost(), url.getPort());
      }
      throw ex;
    } catch (UndeclaredThrowableException ex) {
      throw new IOException(ex.getUndeclaredThrowable());
    } catch (Exception ex) {
      throw new IOException(ex);
    }
    conn.setUseCaches(false);
    conn.setRequestMethod(method);
    if (method.equals(HTTP_POST) || method.equals(HTTP_PUT)) {
      conn.setDoOutput(true);
    }
    conn = configureConnection(conn);
    return conn;
  }

  private HttpURLConnection configureConnection(HttpURLConnection conn)
      throws IOException {
    if (sslFactory != null) {
      HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
      try {
        httpsConn.setSSLSocketFactory(sslFactory.createSSLSocketFactory());
      } catch (GeneralSecurityException ex) {
        throw new IOException(ex);
      }
      httpsConn.setHostnameVerifier(sslFactory.getHostnameVerifier());
    }
    return conn;
  }

  private static String createServiceURL(Path path) throws IOException {
    String str = new URL(path.toString()).toExternalForm();
    if (str.endsWith("/")) {
      str = str.substring(0, str.length() - 1);
    }
    return new URL(str + RENRESTConstants.SERVICE_VERSION + "/").
        toExternalForm();
  }

  private <T> T call(HttpURLConnection conn, Map jsonOutput,
                     int expectedResponse, Class<T> klass) throws IOException {
    return call(conn, jsonOutput, expectedResponse, klass, authRetry);
  }

  private <T> T call(HttpURLConnection conn, Map jsonOutput,
                     int expectedResponse, Class<T> klass, int authRetryCount)
      throws IOException {
    T ret = null;
    try {
      if (jsonOutput != null) {
        writeJson(jsonOutput, conn.getOutputStream());
      }
    } catch (IOException ex) {
      IOUtils.closeStream(conn.getInputStream());
      throw ex;
    }
    if ((conn.getResponseCode() == HttpURLConnection.HTTP_FORBIDDEN
        && (conn.getResponseMessage().equals(ANONYMOUS_REQUESTS_DISALLOWED) ||
        conn.getResponseMessage().contains(INVALID_SIGNATURE)))
        || conn.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      // Ideally, this should happen only when there is an Authentication
      // failure. Unfortunately, the AuthenticationFilter returns 403 when it
      // cannot authenticate (Since a 401 requires Server to send
      // WWW-Authenticate header as well)..
      ReEncryptionClientProvider.this.authToken =
          new DelegationTokenAuthenticatedURL.Token();
      if (authRetryCount > 0) {
        String contentType = conn.getRequestProperty(CONTENT_TYPE);
        String requestMethod = conn.getRequestMethod();
        URL url = conn.getURL();
        conn = createConnection(url, requestMethod);
        conn.setRequestProperty(CONTENT_TYPE, contentType);
        return call(conn, jsonOutput, expectedResponse, klass,
            authRetryCount - 1);
      }
    }
    try {
      AuthenticatedURL.extractToken(conn, authToken);
    } catch (AuthenticationException e) {
      // Ignore the AuthExceptions.. since we are just using the method to
      // extract and set the authToken.. (Workaround till we actually fix
      // AuthenticatedURL properly to set authToken post initialization)
    }
    HttpExceptionUtils.validateResponse(conn, expectedResponse);
    if (conn.getContentType() != null
        && conn.getContentType().trim().toLowerCase()
        .startsWith(APPLICATION_JSON_MIME)
        && klass != null) {
      ObjectMapper mapper = new ObjectMapper();
      InputStream is = null;
      try {
        is = conn.getInputStream();
        ret = mapper.readValue(is, klass);
      } finally {
        IOUtils.closeStream(is);
      }
    }
    return ret;
  }
  public static class RENEncryptedKeyVersion extends EncryptedKeyVersion {
    public RENEncryptedKeyVersion(String keyName, String keyVersionName,
                                  byte[] iv, String encryptedVersionName, byte[] keyMaterial) {
      super(keyName, keyVersionName, iv, new RENKeyVersion(null,
          encryptedVersionName, keyMaterial));
    }
  }

  @SuppressWarnings("rawtypes")
  private static List<EncryptedKeyVersion>
  parseJSONEncKeyVersion(String keyName, List valueList) {
    List<EncryptedKeyVersion> ekvs = new LinkedList<EncryptedKeyVersion>();
    if (!valueList.isEmpty()) {
      for (Object values : valueList) {
        Map valueMap = (Map) values;

        String versionName = checkNotNull(
            (String) valueMap.get(KMSRESTConstants.VERSION_NAME_FIELD),
            KMSRESTConstants.VERSION_NAME_FIELD);

        byte[] iv = Base64.decodeBase64(checkNotNull(
            (String) valueMap.get(KMSRESTConstants.IV_FIELD),
            KMSRESTConstants.IV_FIELD));

        Map encValueMap = checkNotNull((Map)
                valueMap.get(KMSRESTConstants.ENCRYPTED_KEY_VERSION_FIELD),
            KMSRESTConstants.ENCRYPTED_KEY_VERSION_FIELD);

        String encVersionName = checkNotNull((String)
                encValueMap.get(KMSRESTConstants.VERSION_NAME_FIELD),
            KMSRESTConstants.VERSION_NAME_FIELD);

        byte[] encKeyMaterial = Base64.decodeBase64(checkNotNull((String)
                encValueMap.get(KMSRESTConstants.MATERIAL_FIELD),
            KMSRESTConstants.MATERIAL_FIELD));

        ekvs.add(new RENEncryptedKeyVersion(keyName, versionName, iv,
            encVersionName, encKeyMaterial));
      }
    }
    return ekvs;
  }

  private static KeyProvider.KeyVersion parseJSONKeyVersion(Map valueMap) {
    KeyProvider.KeyVersion keyVersion = null;
    if (!valueMap.isEmpty()) {
      byte[] material = (valueMap.containsKey(KMSRESTConstants.MATERIAL_FIELD))
          ? Base64.decodeBase64((String) valueMap.get(KMSRESTConstants.MATERIAL_FIELD))
          : null;
      String versionName = (String)valueMap.get(KMSRESTConstants.VERSION_NAME_FIELD);
      String keyName = (String)valueMap.get(KMSRESTConstants.NAME_FIELD);
      keyVersion = new RENKeyVersion(keyName, versionName, material);
    }
    return keyVersion;
  }

  private static void writeJson(Map map, OutputStream os) throws IOException {
    Writer writer = new OutputStreamWriter(os, Charsets.UTF_8);
    ObjectMapper jsonMapper = new ObjectMapper();
    jsonMapper.writerWithDefaultPrettyPrinter().writeValue(writer, map);
  }

  public static class RENKeyVersion extends KeyProvider.KeyVersion {
    public RENKeyVersion(String keyName, String versionName, byte[] material) {
      super(keyName, versionName, material);
    }
  }

    /**
     * This small class exists to set the timeout values for a connection
     */
    private static class TimeoutConnConfigurator
        implements ConnectionConfigurator {
      private ConnectionConfigurator cc;
      private int timeout;

      /**
       * Sets the timeout and wraps another connection configurator
       * @param timeout - will set both connect and read timeouts - in seconds
       * @param cc - another configurator to wrap - may be null
       */
      public TimeoutConnConfigurator(int timeout, ConnectionConfigurator cc) {
        this.timeout = timeout;
        this.cc = cc;
      }

      /**
       * Calls the wrapped configure() method, then sets timeouts
       * @param conn the {@link HttpURLConnection} instance to configure.
       * @return the connection
       * @throws IOException
       */
      @Override
      public HttpURLConnection configure(HttpURLConnection conn)
          throws IOException {
        if (cc != null) {
          conn = cc.configure(conn);
        }
        conn.setConnectTimeout(timeout * 1000);  // conversion to milliseconds
        conn.setReadTimeout(timeout * 1000);
        return conn;
      }
    }

  }
