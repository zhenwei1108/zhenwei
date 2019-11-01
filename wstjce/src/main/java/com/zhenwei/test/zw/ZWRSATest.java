package com.zhenwei.test.zw;

import cn.com.westone.asymmetric.JCERSAPrivateKey;
import cn.com.westone.asymmetric.JCERSAPublicKey;
import cn.com.westone.asymmetric.RSAPrivateKeyParameters;
import cn.com.westone.asymmetric.RSAPublicKeyParameters;
import cn.com.westone.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import cn.com.westone.bouncycastle.jce.provider.WestoneProvider;
import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Base64;

/**
 * @ClassName ZWRSATest
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/5/24 17:53
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ZWRSATest {

    private static String RSA = "RSA";
    private static String PROVIDER = WestoneProvider.PROVIDER_NAME;
    private static String msg = "this is my rsa test";


    public static void createRSAKeyPairIndex() {
        RSAPublicKeyParameters rsaPublicKeyParameters = new RSAPublicKeyParameters(1, 1024);
        JCERSAPublicKey publicKey = new JCERSAPublicKey(rsaPublicKeyParameters);

        RSAPrivateKeyParameters rsaPrivateKeyParameters = new RSAPrivateKeyParameters(1, 1024);
        JCERSAPrivateKey privateKey = new JCERSAPrivateKey(PrivateKeyInfo.getInstance(rsaPrivateKeyParameters));

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        System.out.println(keyPair);
    }

    public static KeyPair genKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA, PROVIDER);
            generator.initialize(2048);
            KeyPair keyPair = generator.genKeyPair();
            System.out.println("公钥:" + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            System.out.println("私钥:" + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static KeyPair keyGener() {
        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", WestoneProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)));
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            System.out.println("公钥:" + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            System.out.println("私钥:" + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;

    }


    public static void encDec() {
        try {
            KeyPair keyPair = keyGener();

            Cipher cipher = Cipher.getInstance(RSA, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encBytes = cipher.doFinal(msg.getBytes());
            System.out.println("加密结果:" + Base64.getEncoder().encodeToString(encBytes));

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] data = cipher.doFinal(encBytes);

            System.out.println("解密结果:" + new String(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void signDer(){
        try {
            KeyPair keyPair = keyGener();
            Signature signature = Signature.getInstance(RSA, PROVIDER);
            signature.initSign(keyPair.getPrivate());
            signature.update(msg.getBytes());
            byte[] sign = signature.sign();
            System.out.println("签名值为:"+Base64.getEncoder().encodeToString(sign));
            signature.initVerify(keyPair.getPublic());
            signature.update(msg.getBytes());
            boolean verify = signature.verify(sign);
            System.out.println("验签结果为:"+verify);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }


    }


    public static void main(String[] args) {
        Security.addProvider(new WestoneProvider());
        signDer();

    }

}
