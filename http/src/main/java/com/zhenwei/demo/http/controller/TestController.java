package com.zhenwei.demo.http.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName TestController
 * @Description
 * @Date 2019/10/31 13:36
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@RestController
public class TestController {

  @RequestMapping("test")
  public String test(){
    System.out.println("--->>");
    try {
      Thread.sleep(500);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    return "hello world";
  }



}
