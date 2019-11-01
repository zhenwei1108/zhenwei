package com.zhenwei.test.zw.uuid;

import java.util.UUID;

/**
 * @ClassName MyUUID
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/4 18:41
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class MyUUID {

    public static void main(String[] args) {


        UUID uuid = UUID.randomUUID();

        System.out.println(uuid.toString());

    }

}
