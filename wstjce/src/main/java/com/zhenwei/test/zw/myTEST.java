package com.zhenwei.test.zw;

import java.util.Base64;

/**
 * @ClassName myTEST
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/3 15:40
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class myTEST {
    public static void main(String[] args) {
        String s = "2MBlHHzy5+bqVMi16v+7vl7AcjliRCZAeITpl62P97o=";
        byte[] decode = Base64.getDecoder().decode(s);
        String s1 = bytesToHexString(decode);

        System.out.println(s1);

    }

    public static final String bytesToHexString(byte[] bArray) {
        StringBuffer sb = new StringBuffer(bArray.length);
        String sTemp;
        for (int i = 0; i < bArray.length; i++) {
            sTemp = Integer.toHexString(0xFF & bArray[i]);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase()+" ");
        }
        return sb.toString();
    }



}
