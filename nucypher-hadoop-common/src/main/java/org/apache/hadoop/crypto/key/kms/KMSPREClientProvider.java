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
package org.apache.hadoop.crypto.key.kms;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.*;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.CryptoExtension;
import org.apache.hadoop.crypto.key.KeyProviderCryptoExtension.EncryptedKeyVersion;
import org.apache.hadoop.crypto.key.pre.KeyProviderProxyReEncryptionExtension;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.ProviderUtils;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.client.ConnectionConfigurator;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.apache.hadoop.security.token.Token;
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
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import java.util.concurrent.ExecutionException;

/**
 * KMS client <code>KeyPairProvider</code> implementation.
 */
@InterfaceAudience.Private
public class KMSPREClientProvider extends KeyPairProvider implements CryptoExtension,
    KeyProviderProxyReEncryptionExtension.ProxyReEncryptionExtension,
    KeyProviderDelegationTokenExtension.DelegationTokenExtension {

  private static final Logger LOG =
      LoggerFactory.getLogger(KMSPREClientProvider.class);

  private static final String INVALID_SIGNATURE = "Invalid signature";

  private static final String ANONYMOUS_REQUESTS_DISALLOWED = "Anonymous requests are disallowed";

  public static final String TOKEN_KIND = "kms-dt";

  public static final String SCHEME_NAME = "prekms";

  private static final String UTF8 = "UTF-8";

  private static final String CONTENT_TYPE = "Content-Type";
  private static final String APPLICATION_JSON_MIME = "application/json";

  private static final String HTTP_GET = "GET";
  private static final String HTTP_POST = "POST";
  private static final String HTTP_PUT = "PUT";
  private static final String HTTP_DELETE = "DELETE";


  private static final String CONFIG_PREFIX = "hadoop.security.kms.client.";

  /* It's possible to specify a timeout, in seconds, in the config file */
  public static final String TIMEOUT_ATTR = CONFIG_PREFIX + "timeout";
  public static final int DEFAULT_TIMEOUT = 60;

  /* Number of times to retry authentication in the event of auth failure
   * (normally happens due to stale authToken)
   */
  public static final String AUTH_RETRY = CONFIG_PREFIX
      + "authentication.retry-count";
  public static final int DEFAULT_AUTH_RETRY = 1;

  private final ValueQueue<EncryptedKeyVersion> encKeyVersionQueue;

  @Override
  public byte[] generateReEncryptionKey(String encryptionKeyName,
                                                         String destinationKeyVersionName,
                                                         KeyPairMaterial destinationKey)
      throws IOException {
    // TODO
    return null;
  }

  @Override
  public byte[] generateReEncryptionKey(String encryptionKeyVersionName,
                                        String destinationKeyVersionName)
      throws IOException {
    checkNotNull(encryptionKeyVersionName, "encryptionKeyVersionName");
    checkNotNull(encryptionKeyVersionName, "destinationKeyVersionName");

    Map<String, String> params = new HashMap<String, String>();
    params.put(KMSRESTConstants.REK_OP, KMSRESTConstants.REK_GENERATE);
    URL url = createURLFromList(KMSRESTConstants.KEY_VERSION_SRC_DST_RESOURCE,
        Arrays.asList(encryptionKeyVersionName, destinationKeyVersionName),
        KMSRESTConstants.REK_SUB_RESOURCE, params);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    conn.setRequestProperty(CONTENT_TYPE, APPLICATION_JSON_MIME);
    List response = call(conn, null,
        HttpURLConnection.HTTP_OK, List.class);
    byte[] material = null;
    if (!response.isEmpty()) {
      for (Object obj : response) {
        // TODO use this method for a while
        KeyVersion key = parseJSONKeyVersion((Map) obj);
        if (key != null) {
          material = key.getMaterial();
          break;
        }
      }
    }
   return material;
  }

  private class EncryptedQueueRefiller implements
    ValueQueue.QueueRefiller<EncryptedKeyVersion> {

    @Override
    public void fillQueueForKey(String keyName,
        Queue<EncryptedKeyVersion> keyQueue, int numEKVs) throws IOException {
      checkNotNull(keyName, "keyName");
      Map<String, String> params = new HashMap<String, String>();
      params.put(KMSRESTConstants.EEK_OP, KMSRESTConstants.EEK_GENERATE);
      params.put(KMSRESTConstants.EEK_NUM_KEYS, "" + numEKVs);
      URL url = createURL(KMSRESTConstants.KEY_RESOURCE, keyName,
          KMSRESTConstants.EEK_SUB_RESOURCE, params);
      HttpURLConnection conn = createConnection(url, HTTP_GET);
      conn.setRequestProperty(CONTENT_TYPE, APPLICATION_JSON_MIME);
      List response = call(conn, null,
          HttpURLConnection.HTTP_OK, List.class);
      List<EncryptedKeyVersion> ekvs =
          parseJSONEncKeyVersion(keyName, response);
      keyQueue.addAll(ekvs);
    }
  }

  public static class KMSEncryptedKeyVersion extends EncryptedKeyVersion {
    public KMSEncryptedKeyVersion(String keyName, String keyVersionName,
        byte[] iv, String encryptedVersionName, byte[] keyMaterial) {
      super(keyName, keyVersionName, iv, new KMSKeyVersion(null,
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

        ekvs.add(new KMSEncryptedKeyVersion(keyName, versionName, iv,
            encVersionName, encKeyMaterial));
      }
    }
    return ekvs;
  }

  private static KeyVersion parseJSONKeyVersion(Map valueMap) {
    KeyVersion keyVersion = null;
    if (!valueMap.isEmpty()) {
      byte[] material = (valueMap.containsKey(KMSRESTConstants.MATERIAL_FIELD))
          ? Base64.decodeBase64((String) valueMap.get(KMSRESTConstants.MATERIAL_FIELD))
          : null;
      String versionName = (String)valueMap.get(KMSRESTConstants.VERSION_NAME_FIELD);
      String keyName = (String)valueMap.get(KMSRESTConstants.NAME_FIELD);
      keyVersion = new KMSKeyVersion(keyName, versionName, material);
    }
    return keyVersion;
  }

  private static KeyPairVersion parseJSONKeyPairVersion(Map valueMap) {
    KeyPairVersion keyVersion = null;
    if (!valueMap.isEmpty()) {
      byte[] pkMaterial = (valueMap.containsKey(KMSRESTConstants.PUBLIC_MATERIAL_FIELD))
          ? Base64.decodeBase64((String) valueMap.get(KMSRESTConstants.PUBLIC_MATERIAL_FIELD))
          : null;
      byte[] skMaterial = (valueMap.containsKey(KMSRESTConstants.SECRET_MATERIAL_FIELD))
          ? Base64.decodeBase64((String) valueMap.get(KMSRESTConstants.SECRET_MATERIAL_FIELD))
          : null;
      String versionName = (String)valueMap.get(KMSRESTConstants.VERSION_NAME_FIELD);
      String keyName = (String)valueMap.get(KMSRESTConstants.NAME_FIELD);
      keyVersion = new KMSKeyPairVersion(keyName, versionName,
          new KeyPairMaterial(pkMaterial, skMaterial));
    }
    return keyVersion;
  }

  @SuppressWarnings("unchecked")
  private static Metadata parseJSONMetadata(Map valueMap) {
    Metadata metadata = null;
    if (!valueMap.isEmpty()) {
      metadata = new KMSMetadata(
          (String) valueMap.get(KMSRESTConstants.CIPHER_FIELD),
          (Integer) valueMap.get(KMSRESTConstants.LENGTH_FIELD),
          (String) valueMap.get(KMSRESTConstants.DESCRIPTION_FIELD),
          (Map<String, String>) valueMap.get(KMSRESTConstants.ATTRIBUTES_FIELD),
          new Date((Long) valueMap.get(KMSRESTConstants.CREATED_FIELD)),
          (Integer) valueMap.get(KMSRESTConstants.VERSIONS_FIELD));
    }
    return metadata;
  }

  private static void writeJson(Map map, OutputStream os) throws IOException {
    Writer writer = new OutputStreamWriter(os, Charsets.UTF_8);
    ObjectMapper jsonMapper = new ObjectMapper();
    jsonMapper.writerWithDefaultPrettyPrinter().writeValue(writer, map);
  }

  /**
   * The factory to create KMSClientProvider, which is used by the
   * ServiceLoader.
   */
  public static class Factory extends KeyProviderFactory {

    /**
     * This generators expects URIs in the following form :
     * kms://<PROTO>@<AUTHORITY>/<PATH>
     *
     * where :
     * - PROTO = http or https
     * - AUTHORITY = <HOSTS>[:<PORT>]
     * - HOSTS = <HOSTNAME>[;<HOSTS>]
     * - HOSTNAME = string
     * - PORT = integer
     *
     * If multiple hosts are generators, the Factory will create a
     * {@link LoadBalancingKMSClientProvider} that round-robins requests
     * across the provided list of hosts.
     */
    @Override
    public KeyProvider createProvider(URI providerUri, Configuration conf)
        throws IOException {
      if (SCHEME_NAME.equals(providerUri.getScheme())) {
        URL origUrl = new URL(extractKMSPath(providerUri).toString());
        String authority = origUrl.getAuthority();
        // check for ';' which delimits the backup hosts
        if (Strings.isNullOrEmpty(authority)) {
          throw new IOException(
              "No valid authority in kms uri [" + origUrl + "]");
        }
        // Check if port is present in authority
        // In the current scheme, all hosts have to run on the same port
        int port = -1;
        String hostsPart = authority;
        if (authority.contains(":")) {
          String[] t = authority.split(":");
          try {
            port = Integer.parseInt(t[1]);
          } catch (Exception e) {
            throw new IOException(
                "Could not parse port in kms uri [" + origUrl + "]");
          }
          hostsPart = t[0];
        }
        return createProvider(providerUri, conf, origUrl, port, hostsPart);
      }
      return null;
    }

    private KeyPairProvider createProvider(URI providerUri, Configuration conf,
        URL origUrl, int port, String hostsPart) throws IOException {
      String[] hosts = hostsPart.split(";");
      if (hosts.length == 1) {
        return new KMSPREClientProvider(providerUri, conf);
      } else {
        KMSPREClientProvider[] providers = new KMSPREClientProvider[hosts.length];
        for (int i = 0; i < hosts.length; i++) {
          try {
            providers[i] =
                new KMSPREClientProvider(
                    new URI("kms", origUrl.getProtocol(), hosts[i], port,
                        origUrl.getPath(), null, null), conf);
          } catch (URISyntaxException e) {
            throw new IOException("Could not instantiate KMSProvider..", e);
          }
        }
        // TODO add load balancing later
        return null; // new LoadBalancingKMSClientProvider(providers, conf);
      }
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

  private String kmsUrl;
  private SSLFactory sslFactory;
  private ConnectionConfigurator configurator;
  private DelegationTokenAuthenticatedURL.Token authToken;
  private final int authRetry;
  private final UserGroupInformation actualUgi;

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("KMSPREClientProvider[");
    sb.append(kmsUrl).append("]");
    return sb.toString();
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

  public KMSPREClientProvider(URI uri, Configuration conf) throws IOException {
    super(conf);
    kmsUrl = createServiceURL(extractKMSPath(uri));
    if ("https".equalsIgnoreCase(new URL(kmsUrl).getProtocol())) {
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
    encKeyVersionQueue =
        new ValueQueue<EncryptedKeyVersion>(
            conf.getInt(
                CommonConfigurationKeysPublic.KMS_CLIENT_ENC_KEY_CACHE_SIZE,
                CommonConfigurationKeysPublic.
                    KMS_CLIENT_ENC_KEY_CACHE_SIZE_DEFAULT),
            conf.getFloat(
                CommonConfigurationKeysPublic.
                    KMS_CLIENT_ENC_KEY_CACHE_LOW_WATERMARK,
                CommonConfigurationKeysPublic.
                    KMS_CLIENT_ENC_KEY_CACHE_LOW_WATERMARK_DEFAULT),
            conf.getInt(
                CommonConfigurationKeysPublic.
                    KMS_CLIENT_ENC_KEY_CACHE_EXPIRY_MS,
                CommonConfigurationKeysPublic.
                    KMS_CLIENT_ENC_KEY_CACHE_EXPIRY_DEFAULT),
            conf.getInt(
                CommonConfigurationKeysPublic.
                    KMS_CLIENT_ENC_KEY_CACHE_NUM_REFILL_THREADS,
                CommonConfigurationKeysPublic.
                    KMS_CLIENT_ENC_KEY_CACHE_NUM_REFILL_THREADS_DEFAULT),
            new EncryptedQueueRefiller());
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

  private static Path extractKMSPath(URI uri) throws MalformedURLException, IOException {
    return ProviderUtils.unnestUri(uri);
  }

  private static String createServiceURL(Path path) throws IOException {
    String str = new URL(path.toString()).toExternalForm();
    if (str.endsWith("/")) {
      str = str.substring(0, str.length() - 1);
    }
    return new URL(str + KMSRESTConstants.SERVICE_VERSION + "/").
        toExternalForm();
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
      sb.append(kmsUrl);
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
      KMSPREClientProvider.this.authToken =
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

  public static class KMSKeyVersion extends KeyVersion {
    public KMSKeyVersion(String keyName, String versionName, byte[] material) {
      super(keyName, versionName, material);
    }
  }

  public static class KMSKeyPairVersion extends KeyPairVersion {
    public KMSKeyPairVersion(String keyName, String versionName, KeyPairMaterial material) {
      super(keyName, versionName, material);
    }
  }

  @Override
  public KeyPairVersion getKeyPairVersion(String versionName) throws IOException {
    checkNotEmpty(versionName, "versionName");
    URL url = createURL(KMSRESTConstants.KEY_PAIR_VERSION_RESOURCE,
        versionName, null, null);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    Map response = call(conn, null, HttpURLConnection.HTTP_OK, Map.class);
    return parseJSONKeyPairVersion(response);
  }

  @Override
  public KeyVersion getKeyVersion(String versionName) throws IOException {
    checkNotEmpty(versionName, "versionName");
    URL url = createURL(KMSRESTConstants.KEY_VERSION_RESOURCE,
        versionName, null, null);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    Map response = call(conn, null, HttpURLConnection.HTTP_OK, Map.class);
    return parseJSONKeyVersion(response);
  }

  @Override
  public KeyVersion getCurrentKey(String name) throws IOException {
    checkNotEmpty(name, "name");
    URL url = createURL(KMSRESTConstants.KEY_RESOURCE, name,
        KMSRESTConstants.CURRENT_VERSION_SUB_RESOURCE, null);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    Map response = call(conn, null, HttpURLConnection.HTTP_OK, Map.class);
    return parseJSONKeyVersion(response);
  }

  @Override
  @SuppressWarnings("unchecked")
  public List<String> getKeys() throws IOException {
    URL url = createURL(KMSRESTConstants.KEYS_NAMES_RESOURCE, null, null,
        null);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    List response = call(conn, null, HttpURLConnection.HTTP_OK, List.class);
    return (List<String>) response;
  }

  public static class KMSMetadata extends Metadata {
    public KMSMetadata(String cipher, int bitLength, String description,
        Map<String, String> attributes, Date created, int versions) {
      super(cipher, bitLength, description, attributes, created, versions);
    }
  }

  // breaking keyNames into sets to keep resulting URL undler 2000 chars
  private List<String[]> createKeySets(String[] keyNames) {
    List<String[]> list = new ArrayList<String[]>();
    List<String> batch = new ArrayList<String>();
    int batchLen = 0;
    for (String name : keyNames) {
      int additionalLen = KMSRESTConstants.KEY.length() + 1 + name.length();
      batchLen += additionalLen;
      // topping at 1500 to account for initial URL and encoded names
      if (batchLen > 1500) {
        list.add(batch.toArray(new String[batch.size()]));
        batch = new ArrayList<String>();
        batchLen = additionalLen;
      }
      batch.add(name);
    }
    if (!batch.isEmpty()) {
      list.add(batch.toArray(new String[batch.size()]));
    }
    return list;
  }

  @Override
  @SuppressWarnings("unchecked")
  public Metadata[] getKeysMetadata(String ... keyNames) throws IOException {
    List<Metadata> keysMetadata = new ArrayList<Metadata>();
    List<String[]> keySets = createKeySets(keyNames);
    for (String[] keySet : keySets) {
      if (keyNames.length > 0) {
        Map<String, Object> queryStr = new HashMap<String, Object>();
        queryStr.put(KMSRESTConstants.KEY, keySet);
        URL url = createURL(KMSRESTConstants.KEYS_METADATA_RESOURCE, null,
            null, queryStr);
        HttpURLConnection conn = createConnection(url, HTTP_GET);
        List<Map> list = call(conn, null, HttpURLConnection.HTTP_OK, List.class);
        for (Map map : list) {
          keysMetadata.add(parseJSONMetadata(map));
        }
      }
    }
    return keysMetadata.toArray(new Metadata[keysMetadata.size()]);
  }

  private KeyPairVersion createKeyPairInternal(String name, KeyPairMaterial material,
                                       Options options)
      throws NoSuchAlgorithmException, IOException {
    checkNotEmpty(name, "name");
    checkNotNull(options, "options");
    Map<String, Object> jsonKey = new HashMap<>();
    jsonKey.put(KMSRESTConstants.NAME_FIELD, name);
    jsonKey.put(KMSRESTConstants.CIPHER_FIELD, options.getCipher());
    jsonKey.put(KMSRESTConstants.LENGTH_FIELD, options.getBitLength());
    if (material != null) {
      if (material.getPublic() != null)
        jsonKey.put(KMSRESTConstants.PUBLIC_MATERIAL_FIELD,
          Base64.encodeBase64String(material.getPublic()));
      if (material.getPrivate() != null)
        jsonKey.put(KMSRESTConstants.SECRET_MATERIAL_FIELD,
          Base64.encodeBase64String(material.getPrivate()));
    }
    if (options.getDescription() != null) {
      jsonKey.put(KMSRESTConstants.DESCRIPTION_FIELD,
          options.getDescription());
    }
    if (options.getAttributes() != null && !options.getAttributes().isEmpty()) {
      jsonKey.put(KMSRESTConstants.ATTRIBUTES_FIELD, options.getAttributes());
    }
    URL url = createURL(KMSRESTConstants.KEY_PAIRS_RESOURCE, null, null, null);
    HttpURLConnection conn = createConnection(url, HTTP_POST);
    conn.setRequestProperty(CONTENT_TYPE, APPLICATION_JSON_MIME);
    Map response = call(conn, jsonKey, HttpURLConnection.HTTP_CREATED,
        Map.class);
    return parseJSONKeyPairVersion(response);
  }

  @Override
  public KeyPairVersion createKeyPair(String name, Options options)
      throws IOException, NoSuchAlgorithmException {
    return createKeyPairInternal(name, null, options);
  }

  @Override
  public KeyPairVersion createKeyPair(String name, KeyPairMaterial material, Options options)
      throws IOException, NoSuchAlgorithmException {
    return createKeyPairInternal(name, material, options);
  }

  @Override
  public KeyVersion createKey(String name, Options options)
      throws NoSuchAlgorithmException, IOException {
    return createKeyPairInternal(name, null, options).privateToKeyVersion();
  }

  @Override
  public KeyVersion createKey(String name, byte[] material, Options options)
      throws IOException {
    checkNotNull(material, "material");
    try {
      return createKeyPairInternal(name, new KeyPairMaterial(null, material), options).privateToKeyVersion();
    } catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException("It should not happen", ex);
    }
  }

  private KeyPairVersion rollNewVersionPairInternal(String name, KeyPairMaterial material)
      throws NoSuchAlgorithmException, IOException {
    checkNotEmpty(name, "name");
    Map<String, String> jsonMaterial = new HashMap<String, String>();
    if (material != null) {
      if (material.getPublic() != null)
        jsonMaterial.put(KMSRESTConstants.PUBLIC_MATERIAL_FIELD,
          Base64.encodeBase64String(material.getPublic()));
      if (material.getPrivate() != null)
        jsonMaterial.put(KMSRESTConstants.SECRET_MATERIAL_FIELD,
          Base64.encodeBase64String(material.getPrivate()));
    }
    URL url = createURL(KMSRESTConstants.KEY_PAIR_RESOURCE, name, null, null);
    HttpURLConnection conn = createConnection(url, HTTP_POST);
    conn.setRequestProperty(CONTENT_TYPE, APPLICATION_JSON_MIME);
    Map response = call(conn, jsonMaterial,
        HttpURLConnection.HTTP_OK, Map.class);
    KeyPairVersion keyVersion = parseJSONKeyPairVersion(response);
    encKeyVersionQueue.drain(name);
    return keyVersion;
  }

  @Override
  public KeyVersion rollNewVersion(String name)
      throws NoSuchAlgorithmException, IOException {
    return rollNewVersionPairInternal(name, null).privateToKeyVersion();
  }

  @Override
  public KeyPairVersion rollNewVersionPair(String name)
      throws NoSuchAlgorithmException, IOException {
    return rollNewVersionPairInternal(name, null);
  }

  @Override
  public KeyPairVersion rollNewVersionPair(String name, KeyPairMaterial material)
      throws IOException {
    checkNotNull(material, "material");
    try {
      return rollNewVersionPairInternal(name, material);
    } catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException("It should not happen", ex);
    }
  }

  @Override
  public KeyVersion rollNewVersion(String name, byte[] material)
      throws IOException {
    checkNotNull(material, "material");
    try {
      return rollNewVersionPairInternal(name, new KeyPairMaterial(null, material)).privateToKeyVersion();
    } catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException("It should not happen", ex);
    }
  }

  @Override
  public EncryptedKeyVersion generateEncryptedKey(
      String encryptionKeyName) throws IOException, GeneralSecurityException {
    try {
      return encKeyVersionQueue.getNext(encryptionKeyName);
    } catch (ExecutionException e) {
      if (e.getCause() instanceof SocketTimeoutException) {
        throw (SocketTimeoutException)e.getCause();
      }
      throw new IOException(e);
    }
  }

  @SuppressWarnings("rawtypes")
  @Override
  public KeyVersion decryptEncryptedKey(
      EncryptedKeyVersion encryptedKeyVersion) throws IOException,
                                                      GeneralSecurityException {
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
    // TODO
    // Here we need to call  ReEncryptionKeyProviderInterface.transformEncryptedKey(
    //  EncryptedKeyVersion encryptedKeyVersion, String destinationEncryptionKey);
    // to get key, transformated to apropriate key and decrypt it with local private key

    Map<String, String> params = new HashMap<String, String>();
    params.put(KMSRESTConstants.EEK_OP, KMSRESTConstants.EEK_DECRYPT);
    Map<String, Object> jsonPayload = new HashMap<String, Object>();
    jsonPayload.put(KMSRESTConstants.NAME_FIELD,
        encryptedKeyVersion.getEncryptionKeyName());
    jsonPayload.put(KMSRESTConstants.IV_FIELD, Base64.encodeBase64String(
        encryptedKeyVersion.getEncryptedKeyIv()));
    jsonPayload.put(KMSRESTConstants.MATERIAL_FIELD, Base64.encodeBase64String(
            encryptedKeyVersion.getEncryptedKeyVersion().getMaterial()));
    URL url = createURL(KMSRESTConstants.KEY_VERSION_RESOURCE,
        encryptedKeyVersion.getEncryptionKeyVersionName(),
        KMSRESTConstants.EEK_SUB_RESOURCE, params);
    HttpURLConnection conn = createConnection(url, HTTP_POST);
    conn.setRequestProperty(CONTENT_TYPE, APPLICATION_JSON_MIME);
    Map response =
        call(conn, jsonPayload, HttpURLConnection.HTTP_OK, Map.class);
    return parseJSONKeyVersion(response);
  }


  @Override
  public List<KeyPairVersion> getKeyPairVersions(String name) throws IOException {
    checkNotEmpty(name, "name");
    URL url = createURL(KMSRESTConstants.KEY_PAIR_RESOURCE, name,
        KMSRESTConstants.VERSIONS_SUB_RESOURCE, null);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    List response = call(conn, null, HttpURLConnection.HTTP_OK, List.class);
    List<KeyPairVersion> versions = null;
    if (!response.isEmpty()) {
      versions = new ArrayList<>();
      for (Object obj : response) {
        versions.add(parseJSONKeyPairVersion((Map) obj));
      }
    }
    return versions;
  }

  @Override
  public List<KeyVersion> getKeyVersions(String name) throws IOException {
    checkNotEmpty(name, "name");
    URL url = createURL(KMSRESTConstants.KEY_RESOURCE, name,
        KMSRESTConstants.VERSIONS_SUB_RESOURCE, null);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    List response = call(conn, null, HttpURLConnection.HTTP_OK, List.class);
    List<KeyVersion> versions = null;
    if (!response.isEmpty()) {
      versions = new ArrayList<KeyVersion>();
      for (Object obj : response) {
        versions.add(parseJSONKeyVersion((Map) obj));
      }
    }
    return versions;
  }

  @Override
  public Metadata getMetadata(String name) throws IOException {
    checkNotEmpty(name, "name");
    URL url = createURL(KMSRESTConstants.KEY_RESOURCE, name,
        KMSRESTConstants.METADATA_SUB_RESOURCE, null);
    HttpURLConnection conn = createConnection(url, HTTP_GET);
    Map response = call(conn, null, HttpURLConnection.HTTP_OK, Map.class);
    return parseJSONMetadata(response);
  }

  @Override
  public void deleteKey(String name) throws IOException {
    checkNotEmpty(name, "name");
    URL url = createURL(KMSRESTConstants.KEY_RESOURCE, name, null, null);
    HttpURLConnection conn = createConnection(url, HTTP_DELETE);
    call(conn, null, HttpURLConnection.HTTP_OK, null);
  }

  @Override
  public void flush() throws IOException {
    // NOP
    // the client does not keep any local state, thus flushing is not required
    // because of the client.
    // the server should not keep in memory state on behalf of clients either.
  }

  @Override
  public void warmUpEncryptedKeys(String... keyNames)
      throws IOException {
    try {
      encKeyVersionQueue.initializeQueuesForKeys(keyNames);
    } catch (ExecutionException e) {
      throw new IOException(e);
    }
  }

  @Override
  public void drain(String keyName) {
    encKeyVersionQueue.drain(keyName);
  }

  @VisibleForTesting
  public int getEncKeyQueueSize(String keyName) {
    return encKeyVersionQueue.getSize(keyName);
  }

  @Override
  public Token<?>[] addDelegationTokens(final String renewer,
      Credentials credentials) throws IOException {
    Token<?>[] tokens = null;
    Text dtService = getDelegationTokenService();
    Token<?> token = credentials.getToken(dtService);
    if (token == null) {
      final URL url = createURL(null, null, null, null);
      final DelegationTokenAuthenticatedURL authUrl =
          new DelegationTokenAuthenticatedURL(configurator);
      try {
        // 'actualUGI' is the UGI of the user creating the client 
        // It is possible that the creator of the KMSClientProvier
        // calls this method on behalf of a proxyUser (the doAsUser).
        // In which case this call has to be made as the proxy user.
        UserGroupInformation currentUgi = UserGroupInformation.getCurrentUser();
        final String doAsUser = (currentUgi.getAuthenticationMethod() ==
            UserGroupInformation.AuthenticationMethod.PROXY)
                                ? currentUgi.getShortUserName() : null;

        token = actualUgi.doAs(new PrivilegedExceptionAction<Token<?>>() {
          @Override
          public Token<?> run() throws Exception {
            // Not using the cached token here.. Creating a new token here
            // everytime.
            return authUrl.getDelegationToken(url,
                new DelegationTokenAuthenticatedURL.Token(), renewer, doAsUser);
          }
        });
        if (token != null) {
          credentials.addToken(token.getService(), token);
          tokens = new Token<?>[] { token };
        } else {
          throw new IOException("Got NULL as delegation token");
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      } catch (Exception e) {
        throw new IOException(e);
      }
    }
    return tokens;
  }
  
  private Text getDelegationTokenService() throws IOException {
    URL url = new URL(kmsUrl);
    InetSocketAddress addr = new InetSocketAddress(url.getHost(),
        url.getPort());
    Text dtService = SecurityUtil.buildTokenService(addr);
    return dtService;
  }


  /**
   * Shutdown valueQueue executor threads
   */
  @Override
  public void close() throws IOException {
    try {
      encKeyVersionQueue.shutdown();
    } catch (Exception e) {
      throw new IOException(e);
    } finally {
      if (sslFactory != null) {
        sslFactory.destroy();
      }
    }
  }

  @VisibleForTesting
  String getKMSUrl() {
    return kmsUrl;
  }
}
