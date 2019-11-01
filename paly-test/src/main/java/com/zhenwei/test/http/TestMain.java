package com.zhenwei.test.http;

import com.alibaba.fastjson.JSONObject;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;

/**
 * @ClassName Main
 * @Description
 * @Date 2019/10/31 13:44
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class TestMain {

  public static void main(String[] args) {
    String url = "https://localhost:8080/test";
      HttpPost post = new HttpPost(url);

      BasicResponseHandler basicResponseHandler = new BasicResponseHandler();

      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      while (true) {
        JSONObject jsonObject = new JSONObject();
        String format = sdf.format(new Date());
        jsonObject.put("username", format);
        String s = jsonObject.toJSONString();
        post.setEntity(new StringEntity(s, ContentType.APPLICATION_JSON));
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
        String response = null;
        try {
          System.out.println("当前时间:"+format);
          response = HttpClientFactory.getClient().execute(post, basicResponseHandler);
        } catch (Exception e) {
          e.printStackTrace();
        }

        System.out.println(response+":"+format);
      }
  }


}
