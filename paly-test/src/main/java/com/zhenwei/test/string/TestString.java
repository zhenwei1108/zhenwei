package com.zhenwei.test.string;

import org.apache.commons.lang3.StringUtils;

/**
 * @ClassName TestString
 * @Description
 * @Date 2019/9/29 10:52
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class TestString {


  public static void main(String[] args) {

    String s = " 0 ";
    boolean blank = StringUtils.isBlank(s);
    System.out.println(blank);


  }




}
