package com.zhenwei.demo.keypool.util;

import cn.com.westone.bouncycastle.jce.provider.WestoneProvider;
import cn.com.westone.symmetric.JCESM4Key;
import cn.com.westone.symmetric.SM4Parameters;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @ClassName KeyUtil
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/8 19:47
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class KeyUtil {


    public static KeyPair genSM2KeyPair() {
        try {
            KeyPairGenerator sm2Generator = KeyPairGenerator.getInstance("SM2", WestoneProvider.PROVIDER_NAME);
            sm2Generator.initialize(256);
            return sm2Generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static SecretKey genSM4KeyByIndex(int index) {
        try {
            SM4Parameters sm4Parameters = new SM4Parameters(index);
            return new JCESM4Key(sm4Parameters);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
