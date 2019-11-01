package com.zhenwei.test.collections;

import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Set;

/**
 * @ClassName HashMapTest
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/8/3 18:38
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class HashMapTest {


  public static void main(String[] args) {
    HashMap<String, String> map = new HashMap<>();
    map.put("","");
    map.putAll(null);
    Set<Entry<String, String>> entries = map.entrySet();
    String s = map.get("");

    System.out.println(map);


  }


}
