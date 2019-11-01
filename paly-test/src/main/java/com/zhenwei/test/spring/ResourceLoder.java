package com.zhenwei.test.spring;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import org.springframework.core.io.ClassPathResource;

/**
 * @ClassName ResourceLoder
 * @Description
 * @Date 2019/10/29 8:41
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ResourceLoder {

  public static void main(String[] args) {
    loadResourceProperties();
  }


  public static void loadResourceProperties(){

    try {
      ClassPathResource classPathResource = new ClassPathResource("Resource.properties");
      InputStream inputStream = classPathResource.getInputStream();
      InputStreamReader reader = new InputStreamReader(inputStream);
      BufferedReader bufferedReader = new BufferedReader(reader);
      String s = "";
      while ((s = bufferedReader.readLine()) != null){
        System.out.println(s);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }

  }



}
