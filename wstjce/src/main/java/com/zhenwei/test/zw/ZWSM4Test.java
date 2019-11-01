package com.zhenwei.test.zw;

import cn.com.westone.bouncycastle.jce.provider.WestoneProvider;
import cn.com.westone.symmetric.JCESM4Key;
import cn.com.westone.symmetric.SM4Parameters;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * @ClassName ZWSM4Test
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/5/27 14:17
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ZWSM4Test {

    static {
        Security.addProvider(new WestoneProvider());
    }

    // todo 对称密钥是否只支持SM4

    public static SecretKey genSM4Key(int keyIndex) {
        try {
            if(keyIndex > 0) {
                SM4Parameters sm4Parameters = new SM4Parameters(keyIndex);
                JCESM4Key jcesm4Key = new JCESM4Key(sm4Parameters);
                System.out.println(jcesm4Key);
                return jcesm4Key;
            }

            //SM2 256,sm4 128,des 64, aes 128,256
            KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4",WestoneProvider.PROVIDER_NAME);
            keyGenerator.init(128,new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));

            return secretKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void encDec(){
        try {
            SecretKey secretKey = genSM4Key(2);
            Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", WestoneProvider.PROVIDER_NAME);

            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            byte[] encData = cipher.doFinal("哈哈".getBytes());

            cipher.init(Cipher.DECRYPT_MODE,secretKey);
            byte[] bytes = cipher.doFinal(encData);
            String haha = new String(bytes);
            System.out.println(haha);


        } catch (Exception e) {
            e.printStackTrace();
        }


    }




    public static void main(String[] args) {
        encDec();
    }





}
