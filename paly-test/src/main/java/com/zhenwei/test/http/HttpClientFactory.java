package com.zhenwei.test.http;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.security.auth.x500.X500Principal;
import org.apache.http.NoHttpResponseException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * *************************************************************************
 * <pre></pre>
 *
 * @文件名称: HttpClientFactory.java
 * @包 路   径：  com.bjca.ywq.common.util.http.base
 * @版权所有：北京数字认证股份有限公司 (C) 2016
 * @类描述: 对httpClient进行池化管理
 * @版本: V1.0
 * @创建人： hudan
 * @创建时间：2016年5月20日 上午11:56:19
 * @修改记录：
 **/
public class HttpClientFactory {

  private static Logger log = LoggerFactory.getLogger(
      cn.org.bjca.bmca.common.util.http.base.HttpClientFactory.class);

  /**
   * 请求超时时间
   */
  private static final Integer connectionRequestTimeout = 30000;// 300毫秒
  /**
   * 建立连接超时时间
   */
  private static final Integer connectionTimeoutTime = 30000;// 300毫秒
  /**
   * 读取超时
   */
  private static final Integer soTimeoutTime = 3000;// 300 毫秒


  private static final int MaxTotal = 300;
  private static final int DefaultMaxPerRoute = 300;
  private static final int MaxPerRoute = 20;
  private static HttpClientBuilder httpBulder = null;
  static final String CONTENT_TYPE = "Content-Type";
  static final String BASP_CONTENT_TYPE = "application/Json";
  private static KeyStore myKeyStore = null;
  private static KeyStore myTrustStore = null;

  static {
    init();
  }

  public static HttpClient getClient() {
    CloseableHttpClient httpClient = httpBulder.build();
    return httpClient;
  }

  private static void init() {
    try {
      ConnectionSocketFactory plainsf = PlainConnectionSocketFactory.getSocketFactory();
      LayeredConnectionSocketFactory sslsf = SSLConnectionSocketFactory.getSocketFactory();
	        
	        /*SSLContext sslContext = SSLContextBuilder.create()
    		.loadKeyMaterial(myKeyStore, "devops2013")
    		.loadTrustMaterial(myTrustStore, new BaspTrustStrategy()).build();
    
    		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
    		sslContext,
            new String[] { "SSLv2Hello","SSLv3","TLSv1","TLSv1.1","TLSv1.2"},
            null,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());*/

      Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
          .register("http", plainsf)
          .register("https", sslsf)
          .build();

      PoolingHttpClientConnectionManager poolConnManager = new PoolingHttpClientConnectionManager(
          registry);
      // 将最大连接数增加到200
      poolConnManager.setMaxTotal(MaxTotal);
      // 将每个路由基础的连接最大  单个路由 跟总的一致
      poolConnManager.setDefaultMaxPerRoute(DefaultMaxPerRoute);

      SocketConfig socketConfig = SocketConfig.custom().setSoTimeout(soTimeoutTime).build();
      poolConnManager.setDefaultSocketConfig(socketConfig);

      RequestConfig requestConfig = RequestConfig.custom()
          .setConnectionRequestTimeout(connectionRequestTimeout)
          .setConnectTimeout(connectionTimeoutTime)
          .setSocketTimeout(soTimeoutTime).build();

      //请求重试处理
      HttpRequestRetryHandler httpRequestRetryHandler = new HttpRequestRetryHandler() {
        public boolean retryRequest(IOException exception, int executionCount,
            HttpContext context) {
          if (executionCount >= 5) {// 如果已经重试了5次，就放弃
            return false;
          }
          if (exception instanceof NoHttpResponseException) {// 如果服务器丢掉了连接，那么就重试
            return true;
          }
          if (exception instanceof SSLHandshakeException) {// 不要重试SSL握手异常
            return false;
          }
          if (exception instanceof InterruptedIOException) {// 超时
            return true;
          }
          if (exception instanceof UnknownHostException) {// 目标服务器不可达
            return true;
          }
          if (exception instanceof ConnectTimeoutException) {// 连接被拒绝
            return false;
          }
          if (exception instanceof SSLException) {// ssl握手异常
            return false;
          }
          if (exception instanceof ConnectException){
            return true;
          }
          if (exception instanceof SocketException){
            return true;
          }

//          HttpClientContext clientContext = HttpClientContext.adapt(context);
//          HttpRequest request = clientContext.getRequest();
//          // 如果请求是幂等的，就再次尝试
//          if (!(request instanceof HttpEntityEnclosingRequest)) {
//            return true;
//          }
          return false;//ConnectException
        }
      };
      httpBulder = HttpClients.custom()
          .setConnectionManager(poolConnManager)
          .setDefaultRequestConfig(requestConfig)
          .setRetryHandler(httpRequestRetryHandler);

    } catch (Exception e) {
      log.error("httpClient初始化异常了！");
      throw new RuntimeException("初始化HttpClient连接池失败了！", e);
    }
  }


  protected static class BaspTrustStrategy implements TrustStrategy {

    public boolean isTrusted(final X509Certificate[] chain, final String authType)
        throws CertificateException {
      if (chain.length > 0 && myTrustStore != null) {
        for (X509Certificate cert : chain) {
          X500Principal principal = cert.getIssuerX500Principal();
          try {
            List<String> aliases = Collections.list(myTrustStore.aliases());
            for (String alias : aliases) {
              X509Certificate tCert = (X509Certificate) myTrustStore.getCertificate(alias);
              X500Principal tprincipal = tCert.getIssuerX500Principal();
              if (principal.equals(tprincipal)) {
                cert.verify(tCert.getPublicKey());
                return true;
              }
            }
          } catch (KeyStoreException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            log.error("Can't trust this server certificate, error: ", e);
          }
        }
      }
      return false;
    }
  }

}
