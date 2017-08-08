/* ========================================================================
 * Copyright (c) 2015 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

package edu.washington.shibboleth.tools;

import java.lang.IllegalArgumentException;
import java.lang.ThreadLocal;
import java.io.File;
import java.util.List;
import java.io.FileInputStream;
import java.io.IOException;

import java.util.Date;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import java.net.URL;
import java.net.MalformedURLException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import javax.net.ssl.HostnameVerifier;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.config.RequestConfig;

import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;

import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.impl.client.BasicCredentialsProvider;

import org.apache.http.conn.socket.ConnectionSocketFactory;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.util.EntityUtils;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * <code>UWHttpClient</code> provides a webservice client.
 */
public class UWHttpClient {

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(UWHttpClient.class);

    private SSLConnectionSocketFactory socketFactory;

    /** Username if basic auth */
    private String username = null;

    /** Password if basic auth */
    private String password = null;

    /** Cred provider if basic auth */
    private CredentialsProvider credsProvider;

    /** Time, in seconds, to wait for a connection. */
    private int connectTimeLimit = 7;

    /** Time, in seconds, to wait for a response. */
    private int responseTimeLimit = 7;

    /** Accept header. */
    private String acceptHeader = "application/json";

    /** Options header. */
    private String optionsHeader = null;

    /** Connection manager */
    private PoolingHttpClientConnectionManager connectionManager;

    /** Http client **/
    private CloseableHttpClient httpClient;

    /** max connections */
    private int maxConnections = 10;

    private String caCertificateFile;
    private String certificateFile;
    private String keyFile;

    /** authn type **/
    private boolean isBasicAuthn = false;
    private boolean isCertAuthn = false;

    /**
     * Constructor
     */
    public UWHttpClient() {
    }

    /**
     * Initializes the connector and prepares it for use.
     */
    public void initialize() throws IOException {
       log.info("HttpDataSource: initialize");
       
       SSLConnectionSocketFactory sf = getSocketFactory();
       Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create().register("https", sf).build();

       connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
       connectionManager.setMaxTotal(maxConnections);
       connectionManager.setDefaultMaxPerRoute(maxConnections);

       /*
        * Create our client 
        */

       RequestConfig requestConfig = RequestConfig.custom()
            .setConnectTimeout(connectTimeLimit * 1000)
            .setSocketTimeout(responseTimeLimit * 1000).build();

       HttpClientBuilder builder = HttpClients.custom().setConnectionManager(connectionManager).setDefaultRequestConfig(requestConfig);
       if (username!=null && password!=null) {
          CredentialsProvider credsProvider = new BasicCredentialsProvider();
          UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(username, password);
          credsProvider.setCredentials(AuthScope.ANY, usernamePasswordCredentials);
          builder = builder.setDefaultCredentialsProvider(credsProvider);
          log.info("HttpDataSource: added basic creds ");
       }
       httpClient = builder.build(); 
    }

    /**
     * Each thread gets a context
     */
    private static final ThreadLocal<HttpClientContext> clientContext = new ThreadLocal<HttpClientContext>() {
        @Override
        protected HttpClientContext initialValue() {
            return new HttpClientContext();
        }
    };

    /**
     * Retrieve a resource
     */
    public String getResource(String url) {
       String content = null;
       log.debug("web get: " + url);
       HttpGet httpget = new HttpGet(url);
       log.debug("accept=" + acceptHeader + ", options=" + optionsHeader);
       httpget.setHeader("Accept", acceptHeader);
       if (optionsHeader != null) httpget.addHeader("Option-List", optionsHeader);
       try {
          CloseableHttpResponse response = httpClient.execute(httpget, clientContext.get());
          try {
              int sc = response.getStatusLine().getStatusCode();
              if (sc<500) log.debug("status: " + sc);
              else log.error("web get error: url=" + url + ", status="+ sc);
              HttpEntity entity = response.getEntity();
              if (entity != null) {
                  content = EntityUtils.toString(entity);
                  log.trace("content dump:");
                  log.trace(content);
              }
          } finally {
              response.close();
          }
       }  catch (Exception e) {
           log.error("web get error: url=" + url + ", error="+ e);
       }
       return content;
    }

    /**
     * Post a resource
     */
    public String postResource(String url, String data) {
       String content = null;
       log.debug("web post: " + url);
       HttpPost httppost = new HttpPost(url);
       // parameterize this ( by this request? )
       httppost.setHeader("Accept", acceptHeader);
       if (optionsHeader != null) httppost.addHeader("Option-List", optionsHeader);
       try {
          CloseableHttpResponse response = httpClient.execute(httppost, clientContext.get());
          try {
              int sc = response.getStatusLine().getStatusCode();
              if (sc<500) log.debug("status: " + sc);
              else log.error("web post error: url=" + url + ", status="+ sc);
              HttpEntity entity = response.getEntity();
              if (entity != null) {
                  content = EntityUtils.toString(entity);
                  log.trace("content dump:");
                  log.trace(content);
              }
          } finally {
              response.close();
          }
       }  catch (Exception e) {
           log.error("web post error: url=" + url + ", error="+ e);
       }
       return content;
    }


    /**
     * Generate a socket factory using supplied key and trust stores 
     */
    protected SSLConnectionSocketFactory getSocketFactory() throws IOException {
        TrustManager[] trustManagers = null;
        KeyManager[] keyManagers = null;
        
        try {
           /* trust managers */
           if (caCertificateFile != null) {
              KeyStore trustStore;
              int cn = 0;

              log.info("Setting x509 trust from " + caCertificateFile);

              TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
              CertificateFactory cf = CertificateFactory.getInstance("X.509");
              FileInputStream in = new FileInputStream(caCertificateFile);
              Collection certs = cf.generateCertificates(in);

              trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
              trustStore.load(null, null);

              Iterator cit = certs.iterator();
              while (cit.hasNext()) {
                 X509Certificate cert = (X509Certificate) cit.next();
                 log.info(" adding " + cert.getSubjectX500Principal().toString());
                 System.out.println(" adding " + cert.getSubjectX500Principal().toString());
                 trustStore.setCertificateEntry("CACERT" + cn, cert);
                 cn += 1;
              }
              tmf.init(trustStore);
              trustManagers = tmf.getTrustManagers();
           } else {  // no verification
              trustManagers = new TrustManager[] { new X509TrustManager() {
                 public X509Certificate[] getAcceptedIssuers() {
                     return null;
                 }

                 public void checkClientTrusted(X509Certificate[] certs, String authType) {
                     return;
                 }

                 public void checkServerTrusted(X509Certificate[] certs, String authType) {
                     return;
                 }
             }};
           }

           /* key manager */
           if (certificateFile != null && keyFile != null) {
               KeyStore keyStore;
               KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
               keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
               keyStore.load(null, null);

               FileInputStream in = new FileInputStream(certificateFile);
               CertificateFactory cf = CertificateFactory.getInstance("X.509");
               X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
               PKCS1 pkcs = new PKCS1();
               log.info("reading key file: " + keyFile);
               PrivateKey key = pkcs.readKey(keyFile);

               X509Certificate[] chain = new X509Certificate[1];
               chain[0] = cert;
               keyStore.setKeyEntry("CERT", (Key) key, "pw".toCharArray(), chain);
               kmf.init(keyStore, "pw".toCharArray());
               keyManagers = kmf.getKeyManagers();
           }

           /* socket factory */

           SSLContext ctx = SSLContext.getInstance("TLS");
           ctx.init(keyManagers, trustManagers, null);
           return new SSLConnectionSocketFactory(ctx);

        } catch (IOException e) {
           log.error("error reading cert or key error: " + e);
        } catch (KeyStoreException e) {
           log.error("keystore error: " + e);
        } catch (NoSuchAlgorithmException e) {
           log.error("sf error: " + e);
        } catch (KeyManagementException e) {
           log.error("sf error: " + e);
        } catch (CertificateException e) {
           log.error("sf error: " + e);
        } catch (UnrecoverableKeyException e) {
           log.error("sf error: " + e);
        }

        return null;

    }


    /** Bean property setters */

    /**
     * This sets the certificate key for x509 authn
     * 
     * @param i <code>String</code> certificate key file
     */
    public void setKeyFile(String v) {
        keyFile = v;
    }

    /**
     * This sets the certificate for x509 authn
     * 
     * @param i <code>String</code> certificate file
     */
    public void setCertificateFile(String v) {
        certificateFile = v;
    }

    /**
     * This sets the CA certificate file
     * 
     * @param i <code>String</code> CA certificate file
     */
    public void setCaCertificateFile(String v) {
        caCertificateFile = v;
    }


    /**
     * This sets the time in seconds to wait for a connection.
     * 
     * @param i <code>int</code> seconds
     */
    public void setConnectTimeLimit(int i) {
        connectTimeLimit = i;
    }

    /**
     * This sets the time in seconds to wait for a response.
     * 
     * @param i <code>int</code> seconds
     */
    public void setResponseTimeLimit(int i) {
        responseTimeLimit = i;
    }

    /**
     * This sets the maximum connections for the pool
     * 
     * @param i <code>int</code> max connections
     */
    public void setMaxConnections(int i) {
        maxConnections = i;
    }

    /**
     * This sets the accept header
     * 
     * @param s <code>String</code> acceptHeader
     */
    public void setAcceptHeader(String v) {
        acceptHeader = v;
    }

    /**
     * This sets the options header
     * 
     * @param s <code>String</code> optionsHeader
     */
    public void setOptionsHeader(String v) {
        optionsHeader = v;
    }

    /**
     * This sets the basic auth username
     * 
     * @param s <code>String</code> username
     */
    public void setUsername(String u) {
        username = u;
    }

    /**
     * This sets the basic auth password
     * 
     * @param s <code>String</code> password
     */
    public void setPassword(String p) {
        password = p;
    }

    public synchronized void close() {
    }

    private void clearCache() {
    }

}
