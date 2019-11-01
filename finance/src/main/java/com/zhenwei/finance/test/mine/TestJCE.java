package com.zhenwei.finance.test.mine;

import com.sansec.sjj1212.HsmApi;

import java.util.Base64;

/**
 * @ClassName TestJCE
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/5 13:53
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class TestJCE {


    public static void main(String[] args) {
        genKey();
    }



    public static void genKey(){
        try {
            HsmApi hsm = new HsmApi();
            byte[] rsas = hsm.generateKey("RSA", 1);
            System.out.println(Base64.getEncoder().encodeToString(rsas));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }


}
