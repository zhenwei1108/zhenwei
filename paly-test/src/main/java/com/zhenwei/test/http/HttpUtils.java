package com.zhenwei.test.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * *************************************************************************
 * <pre></pre>
 *
 * @文件名称: HttpUtils.java
 * @包 路   径：  com.bjca.ywq.common.util.http.base
 * @版权所有：北京数字认证股份有限公司 (C) 2016
 * @类描述: http工具类
 * @版本: V1.0
 * @创建人： hudan
 * @创建时间：2016年5月20日 上午11:57:13
 * @修改记录：
 **/
public class HttpUtils {

  private static Logger log = LoggerFactory.getLogger(HttpUtils.class);

  public static String excuteGet(String url, Map<String, String> paramMap,
      Map<String, String> headMap, String encoding) {
    HttpGet httpGet = new HttpGet(url);

    List<NameValuePair> params = null;
    if (paramMap != null && !paramMap.isEmpty()) {
      params = new ArrayList<NameValuePair>();
      Set<String> set = paramMap.keySet();
      Iterator<String> it = set.iterator();
      while (it.hasNext()) {
        Object key = it.next();
        Object value = paramMap.get(key);
        NameValuePair nameValuePair = new BasicNameValuePair(key.toString(), value.toString());
        params.add(nameValuePair);
      }
      String str;
      try {
        str = EntityUtils.toString(new UrlEncodedFormEntity(params, encoding), encoding);
        httpGet.setURI(new URI(httpGet.getURI().toString() + "?" + str));
      } catch (Exception e) {
        log.error("get请求 参数设置异常", e);
        throw new RuntimeException("get请求 参数设置异常", e);
      }
    } else {
      log.warn("paramMap is null");
    }

    //header处理
    if (headMap != null && !headMap.isEmpty()) {
      Set<String> set = headMap.keySet();
      Iterator<String> it = set.iterator();
      while (it.hasNext()) {
        String key = it.next();
        String value = headMap.get(key);
        httpGet.setHeader(key, value);
      }
    }

    String resultStr;
    try {
      BasicResponseHandler basicResponseHandler = new BasicResponseHandler();
      resultStr = HttpClientFactory.getClient().execute(httpGet, basicResponseHandler);
    } catch (Exception e) {
      log.error("get请求异常", e);
      throw new RuntimeException("get请求异常", e);
    } finally {
      if (httpGet != null && !httpGet.isAborted()) {
        httpGet.abort();
      }
    }
    return resultStr;
  }

  public static String sendPost(String url, String jsonContent) {
    HttpPost post = new HttpPost(url);
    post.setEntity(new StringEntity(jsonContent, ContentType.APPLICATION_JSON));
    post.setHeader(HttpClientFactory.CONTENT_TYPE, HttpClientFactory.BASP_CONTENT_TYPE);
    String resultStr;
    try {
      BasicResponseHandler basicResponseHandler = new BasicResponseHandler();
      resultStr = HttpClientFactory.getClient().execute(post, basicResponseHandler);
    } catch (Exception e) {
      log.error("post jsonbody请求异常", e);
      throw new RuntimeException("post请求异常", e);
    } finally {
      if (post != null && !post.isAborted()) {
        post.abort();
      }
    }
    return resultStr;
  }

  public static String excutePostForm(String url, Map<String, String> paramMap,
      Map<String, String> headMap, String encoding) {
    HttpPost post = new HttpPost(url);

    //参数处理
    if (paramMap != null && !paramMap.isEmpty()) {
      String paramStr = "";
      Set<String> set = paramMap.keySet();
      Iterator<String> it = set.iterator();
      while (it.hasNext()) {
        Object key = it.next();
        Object value = paramMap.get(key);
        paramStr += "&" + key + "=" + value;
      }
      // 构造最简单的字符串数据
      StringEntity reqEntity = null;
      try {
        reqEntity = new StringEntity(paramStr.substring(1), encoding);
      } catch (Exception e) {
        log.warn("构造参数出错了！", e);
        return "";
      }
      // 设置类型
      reqEntity.setContentType("application/x-www-form-urlencoded");
      post.setEntity(reqEntity);
    } else {
      log.warn("paramMap is null");
      return "";
    }
    //header处理
    if (headMap != null && !headMap.isEmpty()) {
      Set<String> set = headMap.keySet();
      Iterator<String> it = set.iterator();
      while (it.hasNext()) {
        String key = it.next();
        String value = headMap.get(key);
        post.setHeader(key, value);
      }
    }

    String resultStr;
    try {
      BasicResponseHandler basicResponseHandler = new BasicResponseHandler();
      resultStr = HttpClientFactory.getClient().execute(post, basicResponseHandler);
    } catch (Exception e) {
      log.error("post表单请求异常", e);
      throw new RuntimeException("post表单请求异常", e);
    } finally {
      if (post != null && !post.isAborted()) {
        post.abort();
      }
    }
    return resultStr;
  }



}
