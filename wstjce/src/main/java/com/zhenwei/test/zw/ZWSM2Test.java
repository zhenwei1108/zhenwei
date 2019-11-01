package com.zhenwei.test.zw;

import cn.com.westone.asymmetric.JCESM2PrivateKey;
import cn.com.westone.asymmetric.JCESM2PublicKey;
import cn.com.westone.asymmetric.SM2PrivateKeyParameters;
import cn.com.westone.asymmetric.SM2PublicKeyParameters;
import cn.com.westone.bouncycastle.jce.provider.WestoneProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

/**
 * @ClassName ZWSM2Test
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/5/21 11:32
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ZWSM2Test {


    private static String SM2 = "SM2";
    private static String PROVIDER = WestoneProvider.PROVIDER_NAME;
    private static String msg = "this is my test msg";

    static {
        Security.addProvider(new WestoneProvider());
    }

// TODO     RA配置菜单使用p10签发证书

    public static KeyPair testGenSM2() {
        try {

            //产生密钥对

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2", WestoneProvider.PROVIDER_NAME);

            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            System.out.println("公钥:"+Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            System.out.println("私钥:"+Base64.getEncoder().encodeToString(privateKey.getEncoded()));

            return keyPair;


        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void encDec() {
        //加解密
        try {
            Cipher cipher = Cipher.getInstance(SM2, PROVIDER);

            KeyPair keyPair = genSM2KeyPairIndex();
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encByte = cipher.doFinal(msg.getBytes());
            System.out.println("密文:" + Base64.getEncoder().encodeToString(encByte));

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] data = cipher.doFinal(encByte);
            System.out.println("解密结果为:" + new String(data));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }


    public static void signVer() {
        try {
            KeyPair keyPair = genSM2KeyPairIndex();
            Signature signature = Signature.getInstance(SM2, PROVIDER);
            signature.initSign(keyPair.getPrivate());
            signature.update(msg.getBytes());
            byte[] sign = signature.sign();
            System.out.println("签名值为:" + Base64.getEncoder().encodeToString(sign));
            signature.initVerify(keyPair.getPublic());
            signature.update(msg.getBytes());
            boolean verify = signature.verify(sign);
            System.out.println("验签结果为:" + verify);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @Author zhangzhenwei
     * @Date 2019/5/28 10:36
     * @Param []
     * @return java.security.KeyPair
     * @Description genSM2KeyPairIndex TODO 是产生密钥还是获取密钥  初始化密钥1-10实际加密机是多少个
     *
     **/
    public static KeyPair genSM2KeyPairIndex() {

        SM2PublicKeyParameters pkParam = new SM2PublicKeyParameters(4, 256);
        JCESM2PublicKey pk = new JCESM2PublicKey(pkParam);

        SM2PrivateKeyParameters skParam = new SM2PrivateKeyParameters(4, 256);
        JCESM2PrivateKey sk = new JCESM2PrivateKey(skParam);
        KeyPair keyPair = new KeyPair(pk, sk);
        System.out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        return keyPair;

    }


    public static void main(String[] args) {
        testGenSM2();

    }


}
